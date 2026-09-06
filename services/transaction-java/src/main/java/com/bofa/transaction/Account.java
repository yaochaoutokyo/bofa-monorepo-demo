package com.bofa.transaction;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A customer deposit account. Balances are tracked in minor units (cents)
 * as a long to avoid floating point drift, alongside a BigDecimal view for
 * reporting.
 */
public class Account {

    public enum Status { ACTIVE, FROZEN, CLOSED, DORMANT }

    public enum Type { CHECKING, SAVINGS, MONEY_MARKET, CREDIT }

    private final String accountId;
    private final String customerId;
    private final Type type;
    private final String currency;
    private long balanceCents;
    private long holdCents;
    private long overdraftLimitCents;
    private Status status;
    private final Instant openedAt;
    private Instant lastActivityAt;
    private final List<LedgerEntry> ledger = new ArrayList<>();
    private int dailyWithdrawalCount;
    private long dailyWithdrawalCents;

    public Account(String accountId, String customerId, Type type, String currency, long openingBalanceCents) {
        if (accountId == null || accountId.isBlank()) {
            throw new IllegalArgumentException("accountId is required");
        }
        if (customerId == null || customerId.isBlank()) {
            throw new IllegalArgumentException("customerId is required");
        }
        this.accountId = accountId;
        this.customerId = customerId;
        this.type = Objects.requireNonNull(type, "type");
        this.currency = currency == null ? "USD" : currency.toUpperCase();
        this.balanceCents = openingBalanceCents;
        this.status = Status.ACTIVE;
        this.openedAt = Instant.now();
        this.lastActivityAt = this.openedAt;
        this.overdraftLimitCents = type == Type.CHECKING ? 50_00L : 0L;
    }

    public String getAccountId() { return accountId; }
    public String getCustomerId() { return customerId; }
    public Type getType() { return type; }
    public String getCurrency() { return currency; }
    public long getBalanceCents() { return balanceCents; }
    public long getHoldCents() { return holdCents; }
    public Status getStatus() { return status; }
    public Instant getOpenedAt() { return openedAt; }
    public Instant getLastActivityAt() { return lastActivityAt; }
    public long getOverdraftLimitCents() { return overdraftLimitCents; }
    public int getDailyWithdrawalCount() { return dailyWithdrawalCount; }
    public long getDailyWithdrawalCents() { return dailyWithdrawalCents; }

    public BigDecimal getBalance() {
        return BigDecimal.valueOf(balanceCents, 2);
    }

    public long getAvailableCents() {
        return balanceCents - holdCents + overdraftLimitCents;
    }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    public boolean canDebit(long amountCents) {
        if (!isActive()) {
            return false;
        }
        return getAvailableCents() >= amountCents;
    }

    public void setOverdraftLimitCents(long limitCents) {
        if (limitCents < 0) {
            throw new IllegalArgumentException("overdraft limit cannot be negative");
        }
        if (type != Type.CHECKING && limitCents > 0) {
            throw new IllegalStateException("only checking accounts may carry overdraft protection");
        }
        this.overdraftLimitCents = limitCents;
    }

    public void freeze(String reason) {
        if (status == Status.CLOSED) {
            throw new IllegalStateException("cannot freeze a closed account");
        }
        this.status = Status.FROZEN;
        ledger.add(LedgerEntry.memo(accountId, "FREEZE: " + reason));
    }

    public void unfreeze() {
        if (status != Status.FROZEN) {
            throw new IllegalStateException("account is not frozen");
        }
        this.status = Status.ACTIVE;
        ledger.add(LedgerEntry.memo(accountId, "UNFREEZE"));
    }

    public void close() {
        if (balanceCents != 0) {
            throw new IllegalStateException("account balance must be zero before closing");
        }
        if (holdCents != 0) {
            throw new IllegalStateException("account has outstanding holds");
        }
        this.status = Status.CLOSED;
        ledger.add(LedgerEntry.memo(accountId, "CLOSE"));
    }

    public void markDormant() {
        if (status == Status.ACTIVE) {
            status = Status.DORMANT;
        }
    }

    public void reactivate() {
        if (status == Status.DORMANT) {
            status = Status.ACTIVE;
            touch();
        }
    }

    void credit(long amountCents, String reference) {
        if (amountCents <= 0) {
            throw new IllegalArgumentException("credit amount must be positive");
        }
        balanceCents = balanceCents + amountCents;
        ledger.add(LedgerEntry.credit(accountId, amountCents, balanceCents, reference));
        touch();
    }

    void debit(long amountCents, String reference) {
        if (amountCents <= 0) {
            throw new IllegalArgumentException("debit amount must be positive");
        }
        if (!canDebit(amountCents)) {
            throw new InsufficientFundsException(accountId, amountCents, getAvailableCents());
        }
        balanceCents -= amountCents;
        dailyWithdrawalCount++;
        dailyWithdrawalCents += amountCents;
        ledger.add(LedgerEntry.debit(accountId, amountCents, balanceCents, reference));
        touch();
    }

    void placeHold(long amountCents, String reference) {
        if (amountCents <= 0) {
            throw new IllegalArgumentException("hold amount must be positive");
        }
        if (balanceCents - holdCents < amountCents) {
            throw new InsufficientFundsException(accountId, amountCents, balanceCents - holdCents);
        }
        holdCents += amountCents;
        ledger.add(LedgerEntry.memo(accountId, "HOLD " + amountCents + " " + reference));
    }

    void releaseHold(long amountCents, String reference) {
        if (amountCents > holdCents) {
            throw new IllegalArgumentException("release exceeds outstanding holds");
        }
        holdCents -= amountCents;
        ledger.add(LedgerEntry.memo(accountId, "RELEASE " + amountCents + " " + reference));
    }

    void resetDailyCounters() {
        dailyWithdrawalCount = 0;
        dailyWithdrawalCents = 0;
    }

    public List<LedgerEntry> getLedger() {
        return Collections.unmodifiableList(ledger);
    }

    private void touch() {
        lastActivityAt = Instant.now();
    }

    @Override
    public String toString() {
        return "Account{" + accountId + ", " + type + ", " + currency + ", balance=" + getBalance() + ", status=" + status + "}";
    }
}
