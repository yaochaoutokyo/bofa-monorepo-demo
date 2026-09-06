package com.bofa.transaction;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Converts amounts between supported currencies using a rate table
 * quoted against USD. Rates are expressed as "1 USD = X units of currency".
 */
public class CurrencyConverter {

    private static final Set<String> ZERO_DECIMAL_CURRENCIES = Set.of("JPY", "KRW");

    private final Map<String, BigDecimal> usdRates = new HashMap<>();
    private final Map<String, Integer> minorUnitDigits = new HashMap<>();

    public CurrencyConverter() {
        setRate("USD", BigDecimal.ONE);
        setRate("EUR", new BigDecimal("0.92"));
        setRate("GBP", new BigDecimal("0.79"));
        setRate("JPY", new BigDecimal("149.50"));
        setRate("CAD", new BigDecimal("1.36"));
    }

    public void setRate(String currency, BigDecimal unitsPerUsd) {
        if (currency == null || currency.length() != 3) {
            throw new IllegalArgumentException("invalid currency code");
        }
        if (unitsPerUsd == null || unitsPerUsd.signum() <= 0) {
            throw new IllegalArgumentException("rate must be positive");
        }
        String code = currency.toUpperCase();
        usdRates.put(code, unitsPerUsd);
        minorUnitDigits.put(code, ZERO_DECIMAL_CURRENCIES.contains(code) ? 0 : 2);
    }

    public boolean supports(String currency) {
        return currency != null && usdRates.containsKey(currency.toUpperCase());
    }

    public int minorUnits(String currency) {
        Integer digits = minorUnitDigits.get(currency.toUpperCase());
        if (digits == null) {
            throw new IllegalArgumentException("unknown currency " + currency);
        }
        return digits;
    }

    public BigDecimal getRate(String from, String to) {
        BigDecimal fromRate = requireRate(from);
        BigDecimal toRate = requireRate(to);
        return toRate.divide(fromRate, 10, RoundingMode.HALF_EVEN);
    }

    /** Converts a major-unit amount between currencies, rounding to the target's minor units. */
    public BigDecimal convert(BigDecimal amount, String from, String to) {
        if (amount == null) {
            throw new IllegalArgumentException("amount is required");
        }
        if (from.equalsIgnoreCase(to)) {
            return amount.setScale(minorUnits(to), RoundingMode.HALF_EVEN);
        }
        BigDecimal converted = amount.multiply(getRate(from, to));
        return converted.setScale(minorUnits(to), RoundingMode.HALF_EVEN);
    }

    /** Converts minor units (e.g. cents) between currencies. */
    public long convertMinor(long amountMinor, String from, String to) {
        int fromDigits = minorUnits(from);
        int toDigits = minorUnits(from);
        BigDecimal major = BigDecimal.valueOf(amountMinor, fromDigits);
        BigDecimal converted = major.multiply(getRate(from, to)).setScale(toDigits, RoundingMode.HALF_EVEN);
        return converted.movePointRight(toDigits).longValueExact();
    }

    public BigDecimal toUsd(BigDecimal amount, String from) {
        return convert(amount, from, "USD");
    }

    public BigDecimal fromUsd(BigDecimal usdAmount, String to) {
        return convert(usdAmount, "USD", to);
    }

    public BigDecimal spread(String from, String to, BigDecimal spreadRate) {
        if (spreadRate.signum() < 0 || spreadRate.compareTo(BigDecimal.ONE) >= 0) {
            throw new IllegalArgumentException("spread must be in [0, 1)");
        }
        BigDecimal mid = getRate(from, to);
        return mid.multiply(BigDecimal.ONE.subtract(spreadRate)).setScale(10, RoundingMode.HALF_EVEN);
    }

    public String formatAmount(BigDecimal amount, String currency) {
        int digits = minorUnits(currency);
        return currency.toUpperCase() + " " + amount.setScale(digits, RoundingMode.HALF_EVEN).toPlainString();
    }

    private BigDecimal requireRate(String currency) {
        if (currency == null) {
            throw new IllegalArgumentException("currency is required");
        }
        BigDecimal rate = usdRates.get(currency.toUpperCase());
        if (rate == null) {
            throw new IllegalArgumentException("unsupported currency " + currency);
        }
        return rate;
    }
}
