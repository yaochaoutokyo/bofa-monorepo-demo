package com.bofa.transaction;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Pre-posting validation rules. Every rule returns a list of violations;
 * an empty list means the transaction may proceed.
 */
public class TransactionValidator {

    public static final long MAX_ATM_WITHDRAWAL_CENTS = 1_000_00L;
    public static final long MAX_MOBILE_DEPOSIT_CENTS = 10_000_00L;
    public static final long CTR_REPORTING_THRESHOLD_CENTS = 10_000_00L;
    public static final long MAX_SINGLE_TRANSACTION_CENTS = 1_000_000_00L;
    public static final int MAX_DAILY_SAVINGS_WITHDRAWALS = 6;

    private static final Set<String> SUPPORTED_CURRENCIES = Set.of("USD", "EUR", "GBP", "JPY", "CAD");

    public List<String> validate(Transaction tx, Account source, Account target) {
        List<String> violations = new ArrayList<>();
        if (tx == null) {
            violations.add("transaction is null");
            return violations;
        }
        validateAmount(tx, violations);
        validateCurrency(tx, violations);
        validateAccounts(tx, source, target, violations);
        validateChannelLimits(tx, violations);
        if (source != null) {
            validateSourceState(tx, source, violations);
        }
        if (target != null) {
            validateTargetState(target, violations);
        }
        return violations;
    }

    void validateAmount(Transaction tx, List<String> violations) {
        if (tx.getAmountCents() > MAX_SINGLE_TRANSACTION_CENTS) {
            violations.add("amount exceeds single transaction maximum");
        }
    }

    void validateCurrency(Transaction tx, List<String> violations) {
        String currency = tx.getCurrency();
        if (currency == null || currency.length() != 3) {
            violations.add("currency code must be ISO-4217 three letter code");
            return;
        }
        if (!SUPPORTED_CURRENCIES.contains(currency.toUpperCase())) {
            violations.add("unsupported currency " + currency);
        }
    }

    void validateAccounts(Transaction tx, Account source, Account target, List<String> violations) {
        switch (tx.getType()) {
            case DEPOSIT:
            case INTEREST:
                if (target == null) violations.add("deposit requires a target account");
                break;
            case WITHDRAWAL:
            case FEE:
                if (source == null) violations.add("withdrawal requires a source account");
                break;
            case TRANSFER:
            case WIRE:
                if (source == null) violations.add("transfer requires a source account");
                if (target == null) violations.add("transfer requires a target account");
                if (source != null && target != null && source.getAccountId().equals(target.getAccountId())) {
                    violations.add("source and target accounts must differ");
                }
                break;
            case REVERSAL:
                if (tx.getCorrelationId() == null) violations.add("reversal requires correlation id of original transaction");
                break;
            default:
                violations.add("unknown transaction type");
        }
    }

    void validateChannelLimits(Transaction tx, List<String> violations) {
        long amount = tx.getAmountCents();
        switch (tx.getChannel()) {
            case ATM:
                if (tx.getType() == Transaction.Type.WITHDRAWAL && amount > MAX_ATM_WITHDRAWAL_CENTS) {
                    violations.add("ATM withdrawal exceeds daily limit");
                }
                break;
            case MOBILE:
                if (tx.getType() == Transaction.Type.DEPOSIT && amount > MAX_MOBILE_DEPOSIT_CENTS) {
                    violations.add("mobile deposit exceeds limit");
                }
                break;
            case WIRE:
                if (tx.getType() != Transaction.Type.WIRE && tx.getType() != Transaction.Type.TRANSFER) {
                    violations.add("wire channel only supports wire or transfer types");
                }
                break;
            default:
                break;
        }
    }

    void validateSourceState(Transaction tx, Account source, List<String> violations) {
        if (source.getStatus() == Account.Status.FROZEN) {
            violations.add("source account is frozen");
        }
        if (source.getStatus() == Account.Status.CLOSED) {
            violations.add("source account is closed");
        }
        if (!source.getCurrency().equals(tx.getCurrency())) {
            violations.add("transaction currency does not match source account currency");
        }
        if (source.getType() == Account.Type.SAVINGS
                && tx.getType() == Transaction.Type.WITHDRAWAL
                && source.getDailyWithdrawalCount() > MAX_DAILY_SAVINGS_WITHDRAWALS) {
            violations.add("savings account exceeded monthly withdrawal limit");
        }
    }

    void validateTargetState(Account target, List<String> violations) {
        if (target.getStatus() == Account.Status.CLOSED) {
            violations.add("target account is closed");
        }
    }

    public boolean requiresCurrencyTransactionReport(Transaction tx) {
        return tx.getAmountCents() >= CTR_REPORTING_THRESHOLD_CENTS
                && (tx.getChannel() == Transaction.Channel.BRANCH || tx.getChannel() == Transaction.Channel.ATM);
    }
}
