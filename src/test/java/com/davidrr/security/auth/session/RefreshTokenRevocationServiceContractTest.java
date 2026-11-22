package com.davidrr.security.auth.session;

import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.service.impl.RefreshTokenRevocationServiceImpl;
import com.davidrr.security.support.InMemoryRefreshSessionStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Direct sequential effects only; REQUIRES_NEW durability requires a real transactional adapter. */
class RefreshTokenRevocationServiceContractTest {
    @Test
    void revokesOnlyOwnersActiveSessionsAndPreservesExistingLastUse() {
        InMemoryRefreshSessionStore store = new InMemoryRefreshSessionStore();
        Instant prior = Instant.now().minusSeconds(3600);
        RefreshSession fresh = store.save(session("alpha", "fresh").build());
        RefreshSession used = store.save(session("alpha", "used").lastUsedAt(prior).build());
        RefreshSession already = store.save(session("alpha", "already").revoked(true).revokedAt(prior)
                .revocationReason("fixture-old").build());
        RefreshSession foreign = store.save(session("beta", "foreign").build());
        new RefreshTokenRevocationServiceImpl(store).revokeAllActiveTokens("alpha", "fixture-reason");
        for (RefreshSession original : List.of(fresh, used)) {
            RefreshSession saved = store.findById(original.getId()).orElseThrow();
            assertTrue(saved.isRevoked());
            assertEquals("fixture-reason", saved.getRevocationReason());
            assertNotNull(saved.getRevokedAt());
            assertNotNull(saved.getLastUsedAt());
        }
        assertEquals(prior, store.findById(used.getId()).orElseThrow().getLastUsedAt());
        assertEquals(already, store.findById(already.getId()).orElseThrow());
        assertEquals(foreign, store.findById(foreign.getId()).orElseThrow());
        assertTrue(store.findActiveByUsername("alpha").isEmpty());
    }

    @Test
    void emptyAndRepeatedRevocationAreHarmless() {
        InMemoryRefreshSessionStore store = new InMemoryRefreshSessionStore();
        RefreshTokenRevocationServiceImpl service = new RefreshTokenRevocationServiceImpl(store);
        assertDoesNotThrow(() -> service.revokeAllActiveTokens("absent", "fixture-reason"));
        RefreshSession saved = store.save(session("alpha", "current").build());
        service.revokeAllActiveTokens("alpha", "fixture-reason");
        RefreshSession first = store.findById(saved.getId()).orElseThrow();
        service.revokeAllActiveTokens("alpha", "fixture-second");
        assertEquals(first, store.findById(saved.getId()).orElseThrow());
    }

    private static RefreshSession.RefreshSessionBuilder session(String user, String hash) {
        return RefreshSession.builder().username(user).tokenHash(hash).createdAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(3600));
    }
}
