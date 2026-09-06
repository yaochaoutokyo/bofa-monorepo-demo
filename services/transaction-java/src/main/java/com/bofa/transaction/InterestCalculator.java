package com.bofa.transaction;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;

/** Interest accrual for deposit and credit products. */
public class InterestCalculator {

    public enum Compounding { DAILY, MONTHLY, QUARTERLY, ANNUALLY }

    private static final int DAYS_IN_YEAR = 365;
    private static final MathContext MC = new MathContext(20, RoundingMode.HALF_EVEN);

    public BigDecimal annualRateFor(Account account, long balanceCents) {
        switch (account.getType()) {
            case SAVINGS:
                return tieredSavingsRate(balanceCents);
            case MONEY_MARKET:
                return balanceCents >= 25_000_00L ? new BigDecimal("0.0375") : new BigDecimal("0.0250");
            case CHECKING:
                return new BigDecimal("0.0001");
            case CREDIT:
                return new BigDecimal("0.2499");
            default:
                return BigDecimal.ZERO;
        }
    }

    BigDecimal tieredSavingsRate(long balanceCents) {
        if (balanceCents < 0) {
            return BigDecimal.ZERO;
        }
        if (balanceCents < 1_000_00L) {
            return new BigDecimal("0.0100");
        }
        if (balanceCents < 10_000_00L) {
            return new BigDecimal("0.0150");
        }
        if (balanceCents < 100_000_00L) {
            return new BigDecimal("0.0200");
        }
        return new BigDecimal("0.0250");
    }

    /** Simple daily accrual: balance * rate * days / 365, rounded to the cent. */
    public long dailyAccrualCents(long balanceCents, BigDecimal annualRate, int days) {
        if (days < 0) {
            throw new IllegalArgumentException("days cannot be negative");
        }
        if (annualRate == null || annualRate.signum() < 0) {
            throw new IllegalArgumentException("annual rate must be non-negative");
        }
        if (balanceCents <= 0 || days == 0) {
            return 0L;
        }
        BigDecimal balance = BigDecimal.valueOf(balanceCents, 2);
        BigDecimal accrued = balance.multiply(annualRate, MC)
                .multiply(BigDecimal.valueOf(days), MC)
                .divide(BigDecimal.valueOf(DAYS_IN_YEAR), MC);
        return accrued.setScale(2, RoundingMode.DOWN).movePointRight(2).longValueExact();
    }

    public long compoundCents(long principalCents, BigDecimal annualRate, Compounding compounding, int years) {
        if (years < 0) {
            throw new IllegalArgumentException("years cannot be negative");
        }
        int periodsPerYear = periodsPerYear(compounding);
        BigDecimal principal = BigDecimal.valueOf(principalCents, 2);
        BigDecimal periodicRate = annualRate.divide(BigDecimal.valueOf(periodsPerYear), MC);
        BigDecimal growth = BigDecimal.ONE.add(periodicRate).pow(periodsPerYear * years, MC);
        BigDecimal result = principal.multiply(growth, MC).setScale(2, RoundingMode.HALF_EVEN);
        return result.movePointRight(2).longValueExact();
    }

    int periodsPerYear(Compounding compounding) {
        switch (compounding) {
            case DAILY:
                return DAYS_IN_YEAR;
            case MONTHLY:
                return 12;
            case QUARTERLY:
                return 4;
            case ANNUALLY:
                return 1;
            default:
                throw new IllegalArgumentException("unknown compounding " + compounding);
        }
    }

    /** Annual percentage yield for a nominal rate and compounding frequency. */
    public BigDecimal apy(BigDecimal nominalRate, Compounding compounding) {
        int n = periodsPerYear(compounding);
        BigDecimal periodic = nominalRate.divide(BigDecimal.valueOf(n), MC);
        BigDecimal apy = BigDecimal.ONE.add(periodic).pow(n, MC).subtract(BigDecimal.ONE);
        return apy.setScale(6, RoundingMode.HALF_EVEN);
    }

    /** Minimum payment for a credit product: the greater of 1% of balance + interest or $25. */
    public long minimumPaymentCents(long balanceCents, long accruedInterestCents) {
        if (balanceCents <= 0) {
            return 0L;
        }
        long onePercent = balanceCents / 100;
        long computed = onePercent + accruedInterestCents;
        long minimum = Math.max(computed, 25_00L);
        return Math.min(minimum, balanceCents);
    }

    public long lateFeeCents(long minimumPaymentCents, int daysLate) {
        if (daysLate <= 0) {
            return 0L;
        }
        long fee = daysLate > 30 ? 40_00L : 29_00L;
        return Math.min(fee, minimumPaymentCents);
    }
}
