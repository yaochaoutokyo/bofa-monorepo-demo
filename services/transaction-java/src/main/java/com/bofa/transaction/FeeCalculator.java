package com.bofa.transaction;

import java.math.BigDecimal;
import java.math.RoundingMode;

/** Computes schedule-based fees for each transaction type and channel. */
public class FeeCalculator {

    public static final long OUT_OF_NETWORK_ATM_FEE_CENTS = 2_50L;
    public static final long DOMESTIC_WIRE_FEE_CENTS = 30_00L;
    public static final long INTERNATIONAL_WIRE_FEE_CENTS = 45_00L;
    public static final long OVERDRAFT_FEE_CENTS = 35_00L;
    public static final long EXCESS_WITHDRAWAL_FEE_CENTS = 10_00L;
    public static final long MONTHLY_MAINTENANCE_FEE_CENTS = 12_00L;
    public static final long MAINTENANCE_WAIVER_BALANCE_CENTS = 1_500_00L;
    public static final BigDecimal FX_MARKUP_RATE = new BigDecimal("0.03");
    public static final BigDecimal CASH_ADVANCE_RATE = new BigDecimal("0.05");

    public long calculateFee(Transaction tx, Account source) {
        switch (tx.getType()) {
            case WITHDRAWAL:
                return withdrawalFee(tx, source);
            case WIRE:
                return wireFee(tx, source);
            case TRANSFER:
                return transferFee(tx, source);
            case DEPOSIT:
            case INTEREST:
            case REVERSAL:
            case FEE:
                return 0L;
            default:
                throw new IllegalArgumentException("unsupported transaction type " + tx.getType());
        }
    }

    long withdrawalFee(Transaction tx, Account source) {
        long fee = 0L;
        if (tx.getChannel() == Transaction.Channel.ATM && isOutOfNetwork(tx)) {
            fee += OUT_OF_NETWORK_ATM_FEE_CENTS;
        }
        if (source != null && source.getType() == Account.Type.SAVINGS
                && source.getDailyWithdrawalCount() >= TransactionValidator.MAX_DAILY_SAVINGS_WITHDRAWALS) {
            fee += EXCESS_WITHDRAWAL_FEE_CENTS;
        }
        if (source != null && source.getType() == Account.Type.CREDIT) {
            fee += cashAdvanceFee(tx.getAmountCents());
        }
        return fee;
    }

    long wireFee(Transaction tx, Account source) {
        boolean international = source != null && !source.getCurrency().equals(tx.getCurrency());
        long fee = international ? INTERNATIONAL_WIRE_FEE_CENTS : DOMESTIC_WIRE_FEE_CENTS;
        if (international) {
            fee += fxMarkup(tx.getAmountCents());
        }
        return fee;
    }

    long transferFee(Transaction tx, Account source) {
        if (source == null) {
            return 0L;
        }
        if (source.getCustomerId() != null && tx.getTargetAccountId() != null
                && tx.getTargetAccountId().startsWith(source.getCustomerId())) {
            return 0L; // internal transfers between own accounts are free
        }
        return tx.getChannel() == Transaction.Channel.BRANCH ? 3_00L : 0L;
    }

    public long overdraftFee(Account account, long postBalanceCents) {
        if (postBalanceCents >= 0) {
            return 0L;
        }
        if (account.getType() != Account.Type.CHECKING) {
            return 0L;
        }
        return OVERDRAFT_FEE_CENTS;
    }

    public long monthlyMaintenanceFee(Account account, long averageDailyBalanceCents, boolean hasDirectDeposit) {
        if (account.getType() == Account.Type.CREDIT) {
            return 0L;
        }
        if (hasDirectDeposit) {
            return 0L;
        }
        if (averageDailyBalanceCents >= MAINTENANCE_WAIVER_BALANCE_CENTS) {
            return 0L;
        }
        return MONTHLY_MAINTENANCE_FEE_CENTS;
    }

    long fxMarkup(long amountCents) {
        BigDecimal amount = BigDecimal.valueOf(amountCents, 2);
        BigDecimal markup = amount.multiply(FX_MARKUP_RATE).setScale(2, RoundingMode.DOWN);
        return markup.movePointRight(2).longValueExact();
    }

    long cashAdvanceFee(long amountCents) {
        BigDecimal amount = BigDecimal.valueOf(amountCents, 2);
        BigDecimal fee = amount.multiply(CASH_ADVANCE_RATE).setScale(2, RoundingMode.HALF_UP);
        long feeCents = fee.movePointRight(2).longValueExact();
        return Math.max(feeCents, 10_00L);
    }

    boolean isOutOfNetwork(Transaction tx) {
        String memo = tx.getMemo();
        return memo != null && memo.toUpperCase().contains("OON");
    }

    public long applyFeeCap(long feeCents, long amountCents) {
        long cap = amountCents / 10;
        if (cap <= 0) {
            return feeCents;
        }
        return Math.min(feeCents, cap);
    }
}
