package com.bofa.transaction;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Higher level orchestration for transfers: scheduled transfers, cross
 * currency wires and batch settlement on top of the TransactionProcessor.
 */
public class TransferService {

    public static final class ScheduledTransfer {
        private final String scheduleId;
        private final String sourceAccountId;
        private final String targetAccountId;
        private final long amountCents;
        private final LocalDate nextRunDate;
        private final int frequencyDays;
        private int remainingRuns;
        private boolean active = true;

        ScheduledTransfer(String scheduleId, String sourceAccountId, String targetAccountId,
                          long amountCents, LocalDate nextRunDate, int frequencyDays, int remainingRuns) {
            this.scheduleId = scheduleId;
            this.sourceAccountId = sourceAccountId;
            this.targetAccountId = targetAccountId;
            this.amountCents = amountCents;
            this.nextRunDate = nextRunDate;
            this.frequencyDays = frequencyDays;
            this.remainingRuns = remainingRuns;
        }

        public String getScheduleId() { return scheduleId; }
        public long getAmountCents() { return amountCents; }
        public LocalDate getNextRunDate() { return nextRunDate; }
        public int getRemainingRuns() { return remainingRuns; }
        public boolean isActive() { return active; }

        ScheduledTransfer advance() {
            remainingRuns--;
            if (remainingRuns <= 0) {
                active = false;
            }
            return new ScheduledTransfer(scheduleId, sourceAccountId, targetAccountId, amountCents,
                    nextRunDate.plusDays(frequencyDays), frequencyDays, remainingRuns);
        }
    }

    public static final class BatchResult {
        private final int posted;
        private final int declined;
        private final long totalPostedCents;
        private final List<String> declineReasons;

        BatchResult(int posted, int declined, long totalPostedCents, List<String> declineReasons) {
            this.posted = posted;
            this.declined = declined;
            this.totalPostedCents = totalPostedCents;
            this.declineReasons = declineReasons;
        }

        public int getPosted() { return posted; }
        public int getDeclined() { return declined; }
        public long getTotalPostedCents() { return totalPostedCents; }
        public List<String> getDeclineReasons() { return declineReasons; }
    }

    private final TransactionProcessor processor;
    private final CurrencyConverter converter;
    private final List<ScheduledTransfer> schedules = new ArrayList<>();
    private int scheduleCounter = 0;

    public TransferService(TransactionProcessor processor, CurrencyConverter converter) {
        this.processor = processor;
        this.converter = converter;
    }

    public Transaction transfer(String sourceId, String targetId, long amountCents, String memo) {
        Account source = processor.findAccount(sourceId)
                .orElseThrow(() -> new IllegalArgumentException("unknown source account " + sourceId));
        Transaction tx = Transaction.builder(Transaction.Type.TRANSFER)
                .source(sourceId)
                .target(targetId)
                .amountCents(amountCents)
                .currency(source.getCurrency())
                .channel(Transaction.Channel.ONLINE)
                .memo(memo)
                .build();
        return processor.process(tx);
    }

    /**
     * Wire funds to an account denominated in another currency. The debit is
     * taken in the source currency; the credited amount is converted.
     */
    public Transaction internationalWire(String sourceId, String targetId, long amountCents) {
        Account source = processor.findAccount(sourceId)
                .orElseThrow(() -> new IllegalArgumentException("unknown source account " + sourceId));
        Account target = processor.findAccount(targetId)
                .orElseThrow(() -> new IllegalArgumentException("unknown target account " + targetId));

        if (source.getCurrency().equals(target.getCurrency())) {
            Transaction tx = Transaction.builder(Transaction.Type.WIRE)
                    .source(sourceId).target(targetId).amountCents(amountCents)
                    .currency(source.getCurrency()).channel(Transaction.Channel.WIRE).build();
            return processor.process(tx);
        }

        long convertedCents = converter.convertMinor(amountCents, source.getCurrency(), target.getCurrency());
        Transaction debit = Transaction.builder(Transaction.Type.WITHDRAWAL)
                .source(sourceId).amountCents(amountCents).currency(source.getCurrency())
                .channel(Transaction.Channel.WIRE).memo("FX wire to " + targetId).build();
        Transaction credit = Transaction.builder(Transaction.Type.DEPOSIT)
                .target(targetId).amountCents(convertedCents).currency(target.getCurrency())
                .channel(Transaction.Channel.WIRE).memo("FX wire from " + sourceId)
                .correlationId(debit.getTransactionId()).build();

        Transaction debitResult = processor.process(debit);
        if (debitResult.getStatus() != Transaction.Status.POSTED) {
            return debitResult;
        }
        Transaction creditResult = processor.process(credit);
        if (creditResult.getStatus() != Transaction.Status.POSTED) {
            Transaction reversal = Transaction.builder(Transaction.Type.REVERSAL)
                    .correlationId(debit.getTransactionId()).amountCents(amountCents)
                    .currency(source.getCurrency()).build();
            processor.process(reversal);
            processor.getAuditLogger().critical(TransactionProcessor.SYSTEM_ACTOR, "FX_WIRE_ROLLBACK",
                    debit.getTransactionId(), Map.of("reason", creditResult.getDeclineReason()));
        }
        return creditResult;
    }

    public ScheduledTransfer schedule(String sourceId, String targetId, long amountCents,
                                      LocalDate firstRun, int frequencyDays, int runs) {
        if (frequencyDays <= 0) {
            throw new IllegalArgumentException("frequency must be positive");
        }
        if (runs <= 0) {
            throw new IllegalArgumentException("runs must be positive");
        }
        if (firstRun.isBefore(LocalDate.now())) {
            throw new IllegalArgumentException("first run must not be in the past");
        }
        ScheduledTransfer s = new ScheduledTransfer("SCH-" + (++scheduleCounter), sourceId, targetId,
                amountCents, firstRun, frequencyDays, runs);
        schedules.add(s);
        return s;
    }

    public BatchResult runSchedules(LocalDate asOf) {
        int posted = 0;
        int declined = 0;
        long total = 0;
        List<String> reasons = new ArrayList<>();
        List<ScheduledTransfer> next = new ArrayList<>();
        for (ScheduledTransfer s : schedules) {
            if (!s.isActive() || s.getNextRunDate().isAfter(asOf)) {
                next.add(s);
                continue;
            }
            Transaction tx = transfer(s.sourceAccountId, s.targetAccountId, s.amountCents, "Scheduled " + s.getScheduleId());
            if (tx.getStatus() == Transaction.Status.POSTED) {
                posted++;
                total += tx.getAmountCents();
            } else {
                declined++;
                reasons.add(s.getScheduleId() + ": " + tx.getDeclineReason());
            }
            next.add(s.advance());
        }
        schedules.clear();
        schedules.addAll(next);
        return new BatchResult(posted, declined, total, reasons);
    }

    public List<ScheduledTransfer> activeSchedules() {
        List<ScheduledTransfer> active = new ArrayList<>();
        for (ScheduledTransfer s : schedules) {
            if (s.isActive()) {
                active.add(s);
            }
        }
        return active;
    }

    public BigDecimal quoteInTargetCurrency(long amountCents, String from, String to) {
        BigDecimal major = BigDecimal.valueOf(amountCents, converter.minorUnits(from));
        return converter.convert(major, from, to);
    }
}
