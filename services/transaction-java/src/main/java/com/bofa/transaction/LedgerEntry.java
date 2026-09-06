package com.bofa.transaction;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Immutable double-entry style ledger line attached to an account. */
public final class LedgerEntry {

    public enum Kind { CREDIT, DEBIT, MEMO }

    private final String entryId;
    private final String accountId;
    private final Kind kind;
    private final long amountCents;
    private final long runningBalanceCents;
    private final String reference;
    private final Instant postedAt;

    private LedgerEntry(String accountId, Kind kind, long amountCents, long runningBalanceCents, String reference) {
        this.entryId = UUID.randomUUID().toString();
        this.accountId = Objects.requireNonNull(accountId);
        this.kind = kind;
        this.amountCents = amountCents;
        this.runningBalanceCents = runningBalanceCents;
        this.reference = reference == null ? "" : reference;
        this.postedAt = Instant.now();
    }

    public static LedgerEntry credit(String accountId, long amountCents, long runningBalanceCents, String reference) {
        return new LedgerEntry(accountId, Kind.CREDIT, amountCents, runningBalanceCents, reference);
    }

    public static LedgerEntry debit(String accountId, long amountCents, long runningBalanceCents, String reference) {
        return new LedgerEntry(accountId, Kind.DEBIT, amountCents, runningBalanceCents, reference);
    }

    public static LedgerEntry memo(String accountId, String reference) {
        return new LedgerEntry(accountId, Kind.MEMO, 0L, 0L, reference);
    }

    public String getEntryId() { return entryId; }
    public String getAccountId() { return accountId; }
    public Kind getKind() { return kind; }
    public long getAmountCents() { return amountCents; }
    public long getRunningBalanceCents() { return runningBalanceCents; }
    public String getReference() { return reference; }
    public Instant getPostedAt() { return postedAt; }

    public boolean isMonetary() {
        return kind != Kind.MEMO;
    }

    /** Signed amount: credits positive, debits negative, memos zero. */
    public long signedAmountCents() {
        switch (kind) {
            case CREDIT:
                return amountCents;
            case DEBIT:
                return -amountCents;
            default:
                return 0L;
        }
    }

    public String toCsvLine() {
        return String.join(",",
                entryId,
                accountId,
                kind.name(),
                Long.toString(amountCents),
                Long.toString(runningBalanceCents),
                reference.replace(",", ";"),
                postedAt.toString());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LedgerEntry)) return false;
        LedgerEntry that = (LedgerEntry) o;
        return entryId.equals(that.entryId);
    }

    @Override
    public int hashCode() {
        return entryId.hashCode();
    }

    @Override
    public String toString() {
        return kind + " " + amountCents + " (" + reference + ")";
    }
}
