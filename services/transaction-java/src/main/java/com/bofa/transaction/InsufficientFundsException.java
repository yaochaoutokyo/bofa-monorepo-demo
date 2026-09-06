package com.bofa.transaction;

public class InsufficientFundsException extends RuntimeException {

    private final String accountId;
    private final long requestedCents;
    private final long availableCents;

    public InsufficientFundsException(String accountId, long requestedCents, long availableCents) {
        super("Insufficient funds in " + accountId + ": requested " + requestedCents + " available " + availableCents);
        this.accountId = accountId;
        this.requestedCents = requestedCents;
        this.availableCents = availableCents;
    }

    public String getAccountId() { return accountId; }
    public long getRequestedCents() { return requestedCents; }
    public long getAvailableCents() { return availableCents; }

    public long shortfallCents() {
        return requestedCents - availableCents;
    }
}
