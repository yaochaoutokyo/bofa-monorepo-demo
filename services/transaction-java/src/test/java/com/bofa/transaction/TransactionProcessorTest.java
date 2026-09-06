package com.bofa.transaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TransactionProcessorTest {

    @Test
    void depositIsPostedAndIncreasesBalance() {
        TransactionProcessor processor = new TransactionProcessor();
        Account checking = new Account("ACC-1", "CUST-1", Account.Type.CHECKING, "USD", 100_00L);
        processor.registerAccount(checking);

        Transaction deposit = Transaction.builder(Transaction.Type.DEPOSIT)
                .target("ACC-1")
                .amountCents(50_00L)
                .currency("USD")
                .channel(Transaction.Channel.BRANCH)
                .build();

        Transaction result = processor.process(deposit);

        assertEquals(Transaction.Status.POSTED, result.getStatus());
        assertEquals(150_00L, checking.getBalanceCents());
        assertTrue(processor.getAuditLogger().verifyChain());
    }

    @Test
    void withdrawalIsPostedAndDecreasesBalance() {
        TransactionProcessor processor = new TransactionProcessor();
        Account checking = new Account("ACC-2", "CUST-2", Account.Type.CHECKING, "USD", 200_00L);
        processor.registerAccount(checking);

        Transaction withdrawal = Transaction.builder(Transaction.Type.WITHDRAWAL)
                .source("ACC-2")
                .amountCents(75_00L)
                .currency("USD")
                .channel(Transaction.Channel.ONLINE)
                .build();

        Transaction result = processor.process(withdrawal);

        assertEquals(Transaction.Status.POSTED, result.getStatus());
        assertEquals(125_00L, checking.getBalanceCents());
        assertEquals(0L, result.getFeeCents());
    }
}
