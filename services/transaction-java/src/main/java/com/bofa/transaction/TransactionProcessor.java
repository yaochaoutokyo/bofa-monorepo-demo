package com.bofa.transaction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Core posting engine. Validates, applies fees, mutates account balances
 * and writes the audit trail for every transaction outcome.
 */
public class TransactionProcessor {

    public static final String SYSTEM_ACTOR = "transaction-processor";

    private final Map<String, Account> accounts = new HashMap<>();
    private final Map<String, Transaction> transactions = new HashMap<>();
    private final TransactionValidator validator;
    private final FeeCalculator feeCalculator;
    private final AuditLogger auditLogger;

    public TransactionProcessor(TransactionValidator validator, FeeCalculator feeCalculator, AuditLogger auditLogger) {
        this.validator = validator;
        this.feeCalculator = feeCalculator;
        this.auditLogger = auditLogger;
    }

    public TransactionProcessor() {
        this(new TransactionValidator(), new FeeCalculator(), new AuditLogger());
    }

    public void registerAccount(Account account) {
        if (accounts.containsKey(account.getAccountId())) {
            throw new IllegalArgumentException("account already registered: " + account.getAccountId());
        }
        accounts.put(account.getAccountId(), account);
        auditLogger.info(SYSTEM_ACTOR, "ACCOUNT_REGISTERED", account.getAccountId(),
                Map.of("type", account.getType().name(), "currency", account.getCurrency()));
    }

    public Optional<Account> findAccount(String accountId) {
        return Optional.ofNullable(accounts.get(accountId));
    }

    public Optional<Transaction> findTransaction(String transactionId) {
        return Optional.ofNullable(transactions.get(transactionId));
    }

    public AuditLogger getAuditLogger() {
        return auditLogger;
    }

    public Transaction process(Transaction tx) {
        if (tx == null) {
            throw new IllegalArgumentException("transaction is required");
        }
        if (transactions.containsKey(tx.getTransactionId())) {
            return decline(tx, "duplicate transaction id");
        }
        Account source = tx.getSourceAccountId() == null ? null : accounts.get(tx.getSourceAccountId());
        Account target = tx.getTargetAccountId() == null ? null : accounts.get(tx.getTargetAccountId());

        List<String> violations = validator.validate(tx, source, target);
        if (!violations.isEmpty()) {
            return decline(tx, String.join("; ", violations));
        }

        try {
            switch (tx.getType()) {
                case DEPOSIT:
                case INTEREST:
                    return postCredit(tx, target);
                case WITHDRAWAL:
                case FEE:
                    return postDebit(tx, source);
                case TRANSFER:
                case WIRE:
                    return postTransfer(tx, source, target);
                case REVERSAL:
                    return postReversal(tx);
                default:
                    return decline(tx, "unsupported transaction type");
            }
        } catch (InsufficientFundsException e) {
            return decline(tx, "insufficient funds: shortfall " + e.shortfallCents());
        }
    }

    Transaction postCredit(Transaction tx, Account target) {
        target.credit(tx.getAmountCents(), tx.getTransactionId());
        tx.markPosted(0L);
        record(tx);
        auditLogger.info(SYSTEM_ACTOR, "CREDIT_POSTED", tx.getTransactionId(), detailsFor(tx));
        if (validator.requiresCurrencyTransactionReport(tx)) {
            auditLogger.critical(SYSTEM_ACTOR, "CTR_REQUIRED", tx.getTransactionId(), detailsFor(tx));
        }
        return tx;
    }

    Transaction postDebit(Transaction tx, Account source) {
        long fee = feeCalculator.calculateFee(tx, source);
        long total = tx.getAmountCents() + fee;
        source.debit(total, tx.getTransactionId());
        long overdraft = feeCalculator.overdraftFee(source, source.getBalanceCents());
        if (overdraft > 0) {
            source.debit(overdraft, tx.getTransactionId() + "-OD");
            auditLogger.warn(SYSTEM_ACTOR, "OVERDRAFT_FEE", tx.getTransactionId(),
                    Map.of("fee", Long.toString(overdraft), "account", source.getAccountId()));
        }
        tx.markPosted(fee + overdraft);
        record(tx);
        auditLogger.info(SYSTEM_ACTOR, "DEBIT_POSTED", tx.getTransactionId(), detailsFor(tx));
        return tx;
    }

    Transaction postTransfer(Transaction tx, Account source, Account target) {
        long fee = feeCalculator.calculateFee(tx, source);
        source.debit(tx.getAmountCents() + fee, tx.getTransactionId());
        try {
            target.credit(tx.getAmountCents(), tx.getTransactionId());
        } catch (RuntimeException e) {
            source.credit(tx.getAmountCents() + fee, tx.getTransactionId() + "-ROLLBACK");
            return decline(tx, "target credit failed: " + e.getMessage());
        }
        tx.markPosted(fee);
        record(tx);
        auditLogger.info(SYSTEM_ACTOR, "TRANSFER_POSTED", tx.getTransactionId(), detailsFor(tx));
        if (tx.getType() == Transaction.Type.WIRE && tx.getAmountCents() >= TransactionValidator.CTR_REPORTING_THRESHOLD_CENTS) {
            auditLogger.critical(SYSTEM_ACTOR, "LARGE_WIRE", tx.getTransactionId(), detailsFor(tx));
        }
        return tx;
    }

    Transaction postReversal(Transaction tx) {
        Transaction original = transactions.get(tx.getCorrelationId());
        if (original == null) {
            return decline(tx, "original transaction not found");
        }
        if (original.getStatus() != Transaction.Status.POSTED) {
            return decline(tx, "original transaction is not posted");
        }
        Account source = original.getSourceAccountId() == null ? null : accounts.get(original.getSourceAccountId());
        Account target = original.getTargetAccountId() == null ? null : accounts.get(original.getTargetAccountId());
        if (target != null) {
            target.debit(original.getAmountCents(), tx.getTransactionId());
        }
        if (source != null) {
            source.credit(original.getAmountCents(), tx.getTransactionId());
        }
        original.markReversed();
        tx.markPosted(0L);
        record(tx);
        auditLogger.warn(SYSTEM_ACTOR, "REVERSAL_POSTED", tx.getTransactionId(),
                Map.of("original", original.getTransactionId()));
        return tx;
    }

    Transaction decline(Transaction tx, String reason) {
        tx.markDeclined(reason);
        record(tx);
        return tx;
    }

    public Transaction flag(String transactionId, String reason) {
        Transaction tx = transactions.get(transactionId);
        if (tx == null) {
            throw new IllegalArgumentException("unknown transaction " + transactionId);
        }
        tx.markFlagged(reason);
        auditLogger.critical(SYSTEM_ACTOR, "TRANSACTION_FLAGGED", transactionId, Map.of("reason", reason));
        return tx;
    }

    public List<Transaction> historyFor(String accountId) {
        List<Transaction> result = new ArrayList<>();
        for (Transaction tx : transactions.values()) {
            if (tx.involvesAccount(accountId)) {
                result.add(tx);
            }
        }
        result.sort((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()));
        return result;
    }

    public long postedVolumeCents(String accountId) {
        long total = 0;
        for (Transaction tx : historyFor(accountId)) {
            if (tx.getStatus() == Transaction.Status.POSTED) {
                total += tx.getAmountCents();
            }
        }
        return total;
    }

    private void record(Transaction tx) {
        transactions.put(tx.getTransactionId(), tx);
    }

    private static Map<String, String> detailsFor(Transaction tx) {
        Map<String, String> details = new HashMap<>();
        details.put("type", tx.getType().name());
        details.put("amount", Long.toString(tx.getAmountCents()));
        details.put("currency", tx.getCurrency());
        details.put("channel", tx.getChannel().name());
        if (tx.getSourceAccountId() != null) details.put("sourceAccount", tx.getSourceAccountId());
        if (tx.getTargetAccountId() != null) details.put("targetAccount", tx.getTargetAccountId());
        details.put("fee", Long.toString(tx.getFeeCents()));
        return details;
    }
}
