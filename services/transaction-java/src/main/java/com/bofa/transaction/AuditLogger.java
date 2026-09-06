package com.bofa.transaction;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Tamper-evident audit trail. Every entry is chained to the previous one via
 * a SHA-256 hash so regulators can verify the log has not been altered.
 */
public class AuditLogger {

    public enum Severity { INFO, WARN, CRITICAL }

    public static final class Entry {
        private final long sequence;
        private final Instant timestamp;
        private final String actor;
        private final String action;
        private final String subjectId;
        private final Severity severity;
        private final Map<String, String> details;
        private final String previousHash;
        private final String hash;

        Entry(long sequence, Instant timestamp, String actor, String action, String subjectId,
              Severity severity, Map<String, String> details, String previousHash) {
            this.sequence = sequence;
            this.timestamp = timestamp;
            this.actor = actor;
            this.action = action;
            this.subjectId = subjectId;
            this.severity = severity;
            this.details = Collections.unmodifiableMap(new TreeMap<>(details));
            this.previousHash = previousHash;
            this.hash = computeHash();
        }

        public long getSequence() { return sequence; }
        public Instant getTimestamp() { return timestamp; }
        public String getActor() { return actor; }
        public String getAction() { return action; }
        public String getSubjectId() { return subjectId; }
        public Severity getSeverity() { return severity; }
        public Map<String, String> getDetails() { return details; }
        public String getPreviousHash() { return previousHash; }
        public String getHash() { return hash; }

        String canonicalForm() {
            StringBuilder sb = new StringBuilder();
            sb.append(sequence).append('|')
              .append(timestamp.toString()).append('|')
              .append(actor).append('|')
              .append(action).append('|')
              .append(subjectId).append('|')
              .append(severity).append('|');
            for (Map.Entry<String, String> e : details.entrySet()) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
            }
            sb.append('|').append(previousHash);
            return sb.toString();
        }

        private String computeHash() {
            return sha256(canonicalForm());
        }
    }

    private final List<Entry> entries = new ArrayList<>();
    private long nextSequence = 1;
    private String lastHash = "GENESIS";

    public Entry log(String actor, String action, String subjectId, Severity severity, Map<String, String> details) {
        if (actor == null || actor.isBlank()) {
            throw new IllegalArgumentException("actor is required for audit entries");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action is required for audit entries");
        }
        Map<String, String> safeDetails = details == null ? Map.of() : redact(details);
        Entry entry = new Entry(nextSequence++, Instant.now(), actor, action,
                subjectId == null ? "-" : subjectId, severity, safeDetails, lastHash);
        entries.add(entry);
        lastHash = entry.getHash();
        return entry;
    }

    public Entry info(String actor, String action, String subjectId, Map<String, String> details) {
        return log(actor, action, subjectId, Severity.INFO, details);
    }

    public Entry warn(String actor, String action, String subjectId, Map<String, String> details) {
        return log(actor, action, subjectId, Severity.WARN, details);
    }

    public Entry critical(String actor, String action, String subjectId, Map<String, String> details) {
        return log(actor, action, subjectId, Severity.CRITICAL, details);
    }

    public List<Entry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public int size() {
        return entries.size();
    }

    /** Verifies that every entry's hash chain is intact. */
    public boolean verifyChain() {
        String expectedPrevious = "GENESIS";
        long expectedSequence = 1;
        for (Entry e : entries) {
            if (e.getSequence() != expectedSequence) {
                return false;
            }
            if (!e.getPreviousHash().equals(expectedPrevious)) {
                return false;
            }
            if (!e.getHash().equals(sha256(e.canonicalForm()))) {
                return false;
            }
            expectedPrevious = e.getHash();
            expectedSequence++;
        }
        return true;
    }

    /** Redacts values for keys that commonly carry PII before they reach the log. */
    Map<String, String> redact(Map<String, String> details) {
        Map<String, String> out = new TreeMap<>();
        for (Map.Entry<String, String> e : details.entrySet()) {
            String key = e.getKey().toLowerCase();
            String value = e.getValue() == null ? "" : e.getValue();
            if (key.contains("ssn") || key.contains("tax")) {
                out.put(e.getKey(), maskKeepLast(value, 4));
            } else if (key.contains("card") || key.contains("pan")) {
                out.put(e.getKey(), maskKeepLast(value, 4));
            } else if (key.contains("account")) {
                out.put(e.getKey(), value);
            } else {
                out.put(e.getKey(), value);
            }
        }
        return out;
    }

    static String maskKeepLast(String value, int keep) {
        if (value == null || value.length() <= keep) {
            return value;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length() - keep; i++) {
            sb.append(Character.isDigit(value.charAt(i)) || Character.isLetter(value.charAt(i)) ? '*' : value.charAt(i));
        }
        sb.append(value.substring(value.length() - keep));
        return sb.toString();
    }

    static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
