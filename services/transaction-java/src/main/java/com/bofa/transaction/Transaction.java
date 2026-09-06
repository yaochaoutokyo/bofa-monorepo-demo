package com.bofa.transaction;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A request to move money, together with its lifecycle state. */
public class Transaction {

    public enum Type { DEPOSIT, WITHDRAWAL, TRANSFER, FEE, INTEREST, REVERSAL, WIRE }

    public enum Status { PENDING, POSTED, DECLINED, REVERSED }

    public enum Channel { BRANCH, ATM, ONLINE, MOBILE, WIRE, ACH }

    private final String transactionId;
    private final Type type;
    private final String sourceAccountId;
    private final String targetAccountId;
    private final long amountCents;
    private final String currency;
    private final Channel channel;
    private final String memo;
    private final Instant createdAt;
    private Status status;
    private String declineReason;
    private long feeCents;
    private String correlationId;

    private Transaction(Builder b) {
        this.transactionId = b.transactionId != null ? b.transactionId : UUID.randomUUID().toString();
        this.type = Objects.requireNonNull(b.type, "type");
        this.sourceAccountId = b.sourceAccountId;
        this.targetAccountId = b.targetAccountId;
        this.amountCents = b.amountCents;
        this.currency = b.currency == null ? "USD" : b.currency;
        this.channel = b.channel == null ? Channel.ONLINE : b.channel;
        this.memo = b.memo == null ? "" : b.memo;
        this.createdAt = Instant.now();
        this.status = Status.PENDING;
        this.correlationId = b.correlationId;
    }

    public static Builder builder(Type type) {
        return new Builder(type);
    }

    public String getTransactionId() { return transactionId; }
    public Type getType() { return type; }
    public String getSourceAccountId() { return sourceAccountId; }
    public String getTargetAccountId() { return targetAccountId; }
    public long getAmountCents() { return amountCents; }
    public String getCurrency() { return currency; }
    public Channel getChannel() { return channel; }
    public String getMemo() { return memo; }
    public Instant getCreatedAt() { return createdAt; }
    public Status getStatus() { return status; }
    public String getDeclineReason() { return declineReason; }
    public long getFeeCents() { return feeCents; }
    public String getCorrelationId() { return correlationId; }

    void markPosted(long appliedFeeCents) {
        this.status = Status.POSTED;
        this.feeCents = appliedFeeCents;
    }

    void markDeclined(String reason) {
        this.status = Status.DECLINED;
        this.declineReason = reason;
    }

    void markReversed() {
        if (status != Status.POSTED) {
            throw new IllegalStateException("only posted transactions can be reversed");
        }
        this.status = Status.REVERSED;
    }

    public boolean isTerminal() {
        return status == Status.POSTED || status == Status.DECLINED || status == Status.REVERSED;
    }

    public boolean involvesAccount(String accountId) {
        return accountId != null && (accountId.equals(sourceAccountId) || accountId.equals(targetAccountId));
    }

    public static final class Builder {
        private String transactionId;
        private final Type type;
        private String sourceAccountId;
        private String targetAccountId;
        private long amountCents;
        private String currency;
        private Channel channel;
        private String memo;
        private String correlationId;

        private Builder(Type type) {
            this.type = type;
        }

        public Builder id(String id) { this.transactionId = id; return this; }
        public Builder source(String accountId) { this.sourceAccountId = accountId; return this; }
        public Builder target(String accountId) { this.targetAccountId = accountId; return this; }
        public Builder amountCents(long cents) { this.amountCents = cents; return this; }
        public Builder currency(String currency) { this.currency = currency; return this; }
        public Builder channel(Channel channel) { this.channel = channel; return this; }
        public Builder memo(String memo) { this.memo = memo; return this; }
        public Builder correlationId(String id) { this.correlationId = id; return this; }

        public Transaction build() {
            return new Transaction(this);
        }
    }

}
