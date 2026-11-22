package com.davidrr.security.contract;

import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import com.davidrr.security.support.InMemoryRefreshSessionStore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryRefreshSessionStoreContractTest extends RefreshSessionStoreContract {
    @Override
    protected RefreshSessionStore createEmptyStore() { return new InMemoryRefreshSessionStore(); }

    @Test
    void doubleDoesNotPersistMutationsOfInputsSaveResultsOrAnyQueryResult() {
        RefreshSession input = session("alpha", "hash", TIME).build();
        RefreshSession saved = store.save(input);
        input.setUsername("changed-input");
        saved.setUsername("changed-result");
        List<RefreshSession> copies = List.of(store.findById(saved.getId()).orElseThrow(),
                store.findByTokenHash("hash").orElseThrow(), store.findActiveByUsername("alpha").get(0),
                store.findActiveByUsernameOrderByCreatedAtDesc("alpha").get(0),
                store.findExpiredActiveSessions(TIME.plusSeconds(7200)).get(0));
        copies.forEach(s -> s.setUsername("changed-query"));
        assertEquals("alpha", store.findById(saved.getId()).orElseThrow().getUsername());
        RefreshSession batched = store.saveAll(List.of(session("beta", "batch", TIME).build())).get(0);
        batched.setUsername("changed-batch-result");
        assertEquals("beta", store.findByTokenHash("batch").orElseThrow().getUsername());
    }
}
