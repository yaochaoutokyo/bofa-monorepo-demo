package com.bofa.transaction;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/** Produces periodic account statements from ledger entries. */
public class StatementGenerator {

    public static final class Statement {
        private final String accountId;
        private final LocalDate periodStart;
        private final LocalDate periodEnd;
        private final long openingBalanceCents;
        private final long closingBalanceCents;
        private final long totalCreditsCents;
        private final long totalDebitsCents;
        private final int transactionCount;
        private final List<String> lines;

        Statement(String accountId, LocalDate periodStart, LocalDate periodEnd, long openingBalanceCents,
                  long closingBalanceCents, long totalCreditsCents, long totalDebitsCents,
                  int transactionCount, List<String> lines) {
            this.accountId = accountId;
            this.periodStart = periodStart;
            this.periodEnd = periodEnd;
            this.openingBalanceCents = openingBalanceCents;
            this.closingBalanceCents = closingBalanceCents;
            this.totalCreditsCents = totalCreditsCents;
            this.totalDebitsCents = totalDebitsCents;
            this.transactionCount = transactionCount;
            this.lines = lines;
        }

        public String getAccountId() { return accountId; }
        public LocalDate getPeriodStart() { return periodStart; }
        public LocalDate getPeriodEnd() { return periodEnd; }
        public long getOpeningBalanceCents() { return openingBalanceCents; }
        public long getClosingBalanceCents() { return closingBalanceCents; }
        public long getTotalCreditsCents() { return totalCreditsCents; }
        public long getTotalDebitsCents() { return totalDebitsCents; }
        public int getTransactionCount() { return transactionCount; }
        public List<String> getLines() { return lines; }

        public boolean reconciles() {
            return openingBalanceCents + totalCreditsCents - totalDebitsCents == closingBalanceCents;
        }
    }

    private final ZoneId statementZone;

    public StatementGenerator() {
        this(ZoneOffset.UTC);
    }

    public StatementGenerator(ZoneId statementZone) {
        this.statementZone = statementZone;
    }

    public Statement generate(Account account, LocalDate periodStart, LocalDate periodEnd) {
        if (periodEnd.isBefore(periodStart)) {
            throw new IllegalArgumentException("period end must not precede period start");
        }
        List<LedgerEntry> inPeriod = new ArrayList<>();
        long opening = 0;
        boolean openingFound = false;
        for (LedgerEntry entry : account.getLedger()) {
            if (!entry.isMonetary()) {
                continue;
            }
            LocalDate date = toDate(entry.getPostedAt());
            if (date.isBefore(periodStart)) {
                opening = entry.getRunningBalanceCents();
                openingFound = true;
            } else if (!date.isAfter(periodEnd)) {
                inPeriod.add(entry);
            }
        }
        if (!openingFound && !inPeriod.isEmpty()) {
            LedgerEntry first = inPeriod.get(0);
            opening = first.getRunningBalanceCents() - first.signedAmountCents();
        } else if (!openingFound) {
            opening = account.getBalanceCents();
        }

        long credits = 0;
        long debits = 0;
        List<String> lines = new ArrayList<>();
        for (LedgerEntry entry : inPeriod) {
            if (entry.getKind() == LedgerEntry.Kind.CREDIT) {
                credits += entry.getAmountCents();
            } else {
                debits += entry.getAmountCents();
            }
            lines.add(formatLine(entry));
        }
        long closing = inPeriod.isEmpty() ? opening : inPeriod.get(inPeriod.size() - 1).getRunningBalanceCents();
        return new Statement(account.getAccountId(), periodStart, periodEnd, opening, closing,
                credits, debits, inPeriod.size(), lines);
    }

    String formatLine(LedgerEntry entry) {
        String sign = entry.getKind() == LedgerEntry.Kind.CREDIT ? "+" : "-";
        return String.format("%s  %s%s  %s  bal %s",
                toDate(entry.getPostedAt()),
                sign,
                formatCents(entry.getAmountCents()),
                entry.getReference(),
                formatCents(entry.getRunningBalanceCents()));
    }

    static String formatCents(long cents) {
        return BigDecimal.valueOf(cents, 2).toPlainString();
    }

    LocalDate toDate(Instant instant) {
        return instant.atZone(statementZone).toLocalDate();
    }

    public long averageDailyBalanceCents(Account account, LocalDate periodStart, LocalDate periodEnd) {
        long days = periodEnd.toEpochDay() - periodStart.toEpochDay() + 1;
        if (days <= 0) {
            throw new IllegalArgumentException("invalid period");
        }
        Statement statement = generate(account, periodStart, periodEnd);
        long running = statement.getOpeningBalanceCents();
        long sum = 0;
        int index = 0;
        List<LedgerEntry> monetary = new ArrayList<>();
        for (LedgerEntry e : account.getLedger()) {
            if (e.isMonetary()) {
                monetary.add(e);
            }
        }
        for (long d = 0; d < days; d++) {
            LocalDate day = periodStart.plusDays(d);
            while (index < monetary.size() && !toDate(monetary.get(index).getPostedAt()).isAfter(day)) {
                LedgerEntry e = monetary.get(index);
                if (!toDate(e.getPostedAt()).isBefore(periodStart)) {
                    running = e.getRunningBalanceCents();
                }
                index++;
            }
            sum += running;
        }
        return sum / days;
    }

    public String render(Statement statement) {
        StringBuilder sb = new StringBuilder();
        sb.append("STATEMENT FOR ").append(statement.getAccountId()).append('\n');
        sb.append("Period: ").append(statement.getPeriodStart()).append(" to ").append(statement.getPeriodEnd()).append('\n');
        sb.append("Opening balance: ").append(formatCents(statement.getOpeningBalanceCents())).append('\n');
        for (String line : statement.getLines()) {
            sb.append("  ").append(line).append('\n');
        }
        sb.append("Total credits: ").append(formatCents(statement.getTotalCreditsCents())).append('\n');
        sb.append("Total debits: ").append(formatCents(statement.getTotalDebitsCents())).append('\n');
        sb.append("Closing balance: ").append(formatCents(statement.getClosingBalanceCents())).append('\n');
        sb.append(statement.reconciles() ? "RECONCILED" : "OUT OF BALANCE").append('\n');
        return sb.toString();
    }
}
