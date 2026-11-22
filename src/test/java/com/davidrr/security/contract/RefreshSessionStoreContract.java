package com.davidrr.security.contract;

import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** Reusable sequential CRUD harness. An adapter supplies an empty isolated store for each test. */
public abstract class RefreshSessionStoreContract {
    protected RefreshSessionStore store;
    protected static final Instant TIME = Instant.parse("2026-01-01T00:00:00Z");
    protected abstract RefreshSessionStore createEmptyStore();

    @BeforeEach
    protected void resetStore() { store = createEmptyStore(); }

    @Test
    protected void saveReturnsIdentityAndPreservesEveryField() {
        RefreshSession input = session("alpha", "hash-a", TIME).revoked(true).revokedAt(TIME.plusSeconds(4))
                .lastUsedAt(TIME.plusSeconds(3)).revocationReason("fixture-reason").replacedByTokenHash("hash-next").build();
        RefreshSession saved = store.save(input);
        assertNotNull(saved.getId());
        input.setId(saved.getId());
        assertEquals(input, saved);
        assertEquals(input, store.findById(saved.getId()).orElseThrow());
        assertEquals(input, store.findByTokenHash("hash-a").orElseThrow());
    }

    @Test
    protected void updateKeepsIdentityWithoutDuplicatingSession() {
        RefreshSession saved = store.save(session("alpha", "old-hash", TIME).build());
        saved.setTokenHash("new-hash");
        saved.setLastUsedAt(TIME.plusSeconds(1));
        RefreshSession updated = store.save(saved);
        assertEquals(saved, updated);
        assertTrue(store.findByTokenHash("old-hash").isEmpty());
        assertEquals(saved, store.findByTokenHash("new-hash").orElseThrow());
        assertEquals(List.of(saved.getId()), store.findActiveByUsername("alpha").stream().map(RefreshSession::getId).toList());
    }

    @Test
    protected void saveAllMakesEveryResultObservable() {
        List<RefreshSession> saved = store.saveAll(List.of(session("alpha", "h1", TIME).build(), session("beta", "h2", TIME).build()));
        assertEquals(2, saved.size());
        assertEquals(2, saved.stream().map(RefreshSession::getId).distinct().count());
        for (RefreshSession value : saved) assertEquals(value, store.findById(value.getId()).orElseThrow());
    }

    @Test
    protected void absentLookupsAndUserQueriesAreEmpty() {
        assertTrue(store.findById(99L).isEmpty());
        assertTrue(store.findByTokenHash("absent").isEmpty());
        assertTrue(store.findActiveByUsername("absent").isEmpty());
        assertTrue(store.findActiveByUsernameOrderByCreatedAtDesc("absent").isEmpty());
    }

    @Test
    protected void activeQueriesSeparateUsersRevocationsAndCreationOrder() {
        RefreshSession older = store.save(session("alpha", "older", TIME).build());
        RefreshSession newer = store.save(session("alpha", "newer", TIME.plusSeconds(2)).build());
        store.save(session("alpha", "revoked", TIME.plusSeconds(4)).revoked(true).build());
        store.save(session("beta", "other", TIME.plusSeconds(6)).build());
        assertEquals(Set.of(older.getId(), newer.getId()), store.findActiveByUsername("alpha").stream()
                .map(RefreshSession::getId).collect(Collectors.toSet()));
        assertEquals(List.of(newer.getId(), older.getId()), store.findActiveByUsernameOrderByCreatedAtDesc("alpha").stream()
                .map(RefreshSession::getId).toList());
    }

    @Test
    protected void expiredQueryUsesStrictCutoffAndExcludesRevokedSessions() {
        RefreshSession expired = store.save(session("alpha", "past", TIME).expiresAt(TIME.minusSeconds(1)).build());
        store.save(session("alpha", "equal", TIME).expiresAt(TIME).build());
        store.save(session("beta", "future", TIME).build());
        store.save(session("alpha", "revoked-past", TIME).expiresAt(TIME.minusSeconds(1)).revoked(true).build());
        assertEquals(List.of(expired.getId()), store.findExpiredActiveSessions(TIME).stream().map(RefreshSession::getId).toList());
    }

    @Test
    protected void deleteRemovesIdentityAndHashWithoutRemovingOtherSessions() {
        RefreshSession removed = store.save(session("alpha", "removed", TIME).build());
        RefreshSession retained = store.save(session("alpha", "retained", TIME).build());
        store.deleteById(removed.getId());
        assertTrue(store.findById(removed.getId()).isEmpty());
        assertTrue(store.findByTokenHash("removed").isEmpty());
        assertEquals(retained, store.findById(retained.getId()).orElseThrow());
    }

    protected static RefreshSession.RefreshSessionBuilder session(String user, String hash, Instant created) {
        return RefreshSession.builder().username(user).tokenHash(hash).createdAt(created).expiresAt(created.plusSeconds(3600))
                .ip("192.0.2.10").userAgent("synthetic-agent");
    }
}
