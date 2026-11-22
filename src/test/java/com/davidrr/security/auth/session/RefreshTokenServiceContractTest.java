package com.davidrr.security.auth.session;

import com.davidrr.security.audit.SecurityAuditService;
import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.exception.*;
import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.service.RefreshTokenRevocationService;
import com.davidrr.security.auth.session.service.impl.RefreshTokenServiceImpl;
import com.davidrr.security.support.InMemoryRefreshSessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** REF-01/02: sequential effects in a copying double; no transaction, fence or concurrency proof. */
class RefreshTokenServiceContractTest {
    private final InMemoryRefreshSessionStore store = new InMemoryRefreshSessionStore();
    private final RefreshTokenRevocationService revocation = mock(RefreshTokenRevocationService.class);
    private final SessionFingerprint fingerprint = new SessionFingerprint("192.0.2.30", "synthetic-agent");
    private RefreshTokenServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenServiceImpl(revocation, store, mock(SecurityAuditService.class));
        // Local wiring of an @Value field, not an assertion about internal field names.
        ReflectionTestUtils.setField(service, "refreshExpirationDays", 3L);
    }

    @Test
    void creationReturnsLegacyRandomFormatAndPersistsOnlyIndependentDigest() throws Exception {
        Instant before = Instant.now();
        String plain = service.createRefreshToken("alpha", fingerprint);
        Instant after = Instant.now();
        assertTrue(plain.matches("[A-Za-z0-9_-]+"));
        assertEquals(32, Base64.getUrlDecoder().decode(plain).length);
        assertTrue(store.findByTokenHash(plain).isEmpty());
        RefreshSession persisted = store.findByTokenHash(digest(plain)).orElseThrow();
        assertNotEquals(plain, persisted.getTokenHash());
        assertEquals("alpha", persisted.getUsername());
        assertEquals(fingerprint.ip(), persisted.getIp());
        assertEquals(fingerprint.userAgent(), persisted.getUserAgent());
        assertFalse(persisted.isRevoked());
        assertNull(persisted.getLastUsedAt());
        assertNull(persisted.getRevokedAt());
        assertNull(persisted.getReplacedByTokenHash());
        assertFalse(persisted.getCreatedAt().isBefore(before));
        assertFalse(persisted.getCreatedAt().isAfter(after));
        assertEquals(Duration.ofDays(3), Duration.between(persisted.getCreatedAt(), persisted.getExpiresAt()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "synthetic-unknown"})
    void missingBlankAndUnknownTokensAreRejectedBySensitiveOperations(String token) {
        assertThrows(RefreshTokenInvalidException.class, () -> service.rotate(token, fingerprint));
        assertThrows(RefreshTokenInvalidException.class, () -> service.validateAndGetUsername(token));
        assertThrows(RefreshTokenInvalidException.class, () -> service.findSessionByToken(token));
        assertThrows(RefreshTokenInvalidException.class, () -> service.getActiveSessions(token));
        assertThrows(RefreshTokenInvalidException.class, () -> service.revokeSession(token, 7L));
        verifyNoInteractions(revocation);
    }

    @Test
    void validLookupAndValidationResolveOwnerAndSaveLastUse() throws Exception {
        RefreshSession current = seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        assertEquals(current.getId(), service.findSessionByToken("synthetic-current").getId());
        assertEquals("alpha", service.validateAndGetUsername("synthetic-current"));
        assertNotNull(store.findById(current.getId()).orElseThrow().getLastUsedAt());
    }

    @Test
    void sequentialRotationLinksOldDigestToDistinctSuccessor() throws Exception {
        RefreshSession old = seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        RefreshRotationResult rotated = service.rotate("synthetic-current", fingerprint);
        assertEquals("alpha", rotated.username());
        assertNotEquals("synthetic-current", rotated.refreshToken());
        RefreshSession previous = store.findById(old.getId()).orElseThrow();
        RefreshSession successor = store.findByTokenHash(digest(rotated.refreshToken())).orElseThrow();
        assertTrue(previous.isRevoked());
        assertNotNull(previous.getRevokedAt());
        assertNotNull(previous.getLastUsedAt());
        assertEquals("ROTATED", previous.getRevocationReason());
        assertEquals(successor.getTokenHash(), previous.getReplacedByTokenHash());
        assertNotEquals(previous.getId(), successor.getId());
        assertFalse(successor.isRevoked());
        assertEquals("alpha", successor.getUsername());
        assertTrue(store.findByTokenHash(rotated.refreshToken()).isEmpty());
        assertEquals(1, store.findActiveByUsername("alpha").size());
    }

    @Test
    void recognizedReplayIsRejectedAndRequestsRevocationWithoutReturningCredentials() throws Exception {
        seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        service.rotate("synthetic-current", fingerprint);
        assertThrows(RefreshTokenReuseException.class, () -> service.rotate("synthetic-current", fingerprint));
        verify(revocation).revokeAllActiveTokens("alpha", "REUSE_DETECTED");
        // The mock invocation is NOT evidence that revocation commits after the exception.
    }

    @ParameterizedTest
    @ValueSource(strings = {"rotate", "validate", "list", "revoke"})
    void expiredTokensCannotPerformSensitiveOperations(String operation) throws Exception {
        seed("synthetic-expired", "alpha", Instant.now().minusSeconds(3600));
        assertThrows(RefreshTokenExpiredException.class, () -> operate(operation, "synthetic-expired"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"rotate", "validate", "list", "revoke"})
    void revokedTokensCannotPerformSensitiveOperations(String operation) throws Exception {
        RefreshSession current = seed("synthetic-revoked", "alpha", Instant.now().plusSeconds(3600));
        current.setRevoked(true);
        current.setRevocationReason("ROTATED");
        store.save(current);
        assertThrows(RefreshTokenReuseException.class, () -> operate(operation, "synthetic-revoked"));
    }

    @Test
    void logoutIsIdempotentForCurrentSessionAndToleratesMissingToken() throws Exception {
        RefreshSession current = seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        service.revoke("synthetic-current");
        RefreshSession revoked = store.findById(current.getId()).orElseThrow();
        assertTrue(revoked.isRevoked());
        assertEquals("LOGOUT", revoked.getRevocationReason());
        assertNotNull(revoked.getRevokedAt());
        service.revoke("synthetic-current");
        assertEquals(revoked, store.findById(current.getId()).orElseThrow());
        assertDoesNotThrow(() -> service.revoke(null));
        assertDoesNotThrow(() -> service.revoke(" "));
        assertDoesNotThrow(() -> service.revoke("synthetic-unknown"));
    }

    @Test
    void revokeAllDelegatesWithLogoutReason() {
        service.revokeAll("alpha");
        verify(revocation).revokeAllActiveTokens("alpha", "LOGOUT_ALL");
    }

    @Test
    void listingMapsOnlyOwnersActiveSessionsAndMarksCurrentWithoutExposingHash() throws Exception {
        RefreshSession current = seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        current.setLastUsedAt(Instant.now().minusSeconds(60));
        store.save(current);
        RefreshSession other = seed("synthetic-other", "alpha", Instant.now().plusSeconds(3600));
        seed("synthetic-foreign", "beta", Instant.now().plusSeconds(3600));
        RefreshSession revoked = seed("synthetic-revoked", "alpha", Instant.now().plusSeconds(3600));
        revoked.setRevoked(true); store.save(revoked);
        List<SessionResponse> results = service.getActiveSessions("synthetic-current");
        assertEquals(Set.of(current.getId(), other.getId()), results.stream().map(SessionResponse::id).collect(java.util.stream.Collectors.toSet()));
        SessionResponse active = results.stream().filter(SessionResponse::current).findFirst().orElseThrow();
        assertEquals(1, results.stream().filter(SessionResponse::current).count());
        assertEquals(current.getId(), active.id());
        assertEquals(current.getCreatedAt(), active.createdAt());
        assertEquals(current.getLastUsedAt(), active.lastUsedAt());
        assertEquals(current.getExpiresAt(), active.expiresAt());
        assertEquals(current.getIp(), active.ip());
        assertEquals(current.getUserAgent(), active.userAgent());
        assertNotNull(active.device());
        assertFalse(active.device().isBlank());
        // JSON field shape / absence of hash is owned by AdditionalJsonContractTest in 02A.
    }

    @Test
    void targetedRevocationRejectsForeignOrMissingSessionAndLeavesThemUntouched() throws Exception {
        seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        RefreshSession foreign = seed("synthetic-foreign", "beta", Instant.now().plusSeconds(3600));
        assertThrows(SessionNotFoundException.class, () -> service.revokeSession("synthetic-current", foreign.getId()));
        assertEquals(foreign, store.findById(foreign.getId()).orElseThrow());
        assertThrows(SessionNotFoundException.class, () -> service.revokeSession("synthetic-current", Long.MAX_VALUE));
    }

    @Test
    void targetedRevocationPersistsOwnedSessionAndIsRepeatable() throws Exception {
        seed("synthetic-current", "alpha", Instant.now().plusSeconds(3600));
        RefreshSession target = seed("synthetic-target", "alpha", Instant.now().plusSeconds(3600));
        service.revokeSession("synthetic-current", target.getId());
        RefreshSession revoked = store.findById(target.getId()).orElseThrow();
        assertTrue(revoked.isRevoked());
        assertEquals("SESSION_REVOKED", revoked.getRevocationReason());
        assertNotNull(revoked.getRevokedAt());
        service.revokeSession("synthetic-current", target.getId());
        assertEquals(revoked, store.findById(target.getId()).orElseThrow());
    }

    @Test
    void cleanupRevokesExpiredActiveSessionsButPreservesFutureAndPreviouslyRevokedOnes() throws Exception {
        RefreshSession expired = seed("synthetic-expired", "alpha", Instant.now().minusSeconds(3600));
        RefreshSession future = seed("synthetic-future", "alpha", Instant.now().plusSeconds(3600));
        RefreshSession previous = seed("synthetic-revoked", "beta", Instant.now().minusSeconds(3600));
        previous.setRevoked(true); previous.setRevocationReason("fixture-old"); store.save(previous);
        service.cleanupExpired();
        RefreshSession cleaned = store.findById(expired.getId()).orElseThrow();
        assertTrue(cleaned.isRevoked());
        assertEquals("EXPIRED", cleaned.getRevocationReason());
        assertNotNull(cleaned.getRevokedAt());
        assertEquals(future, store.findById(future.getId()).orElseThrow());
        assertEquals(previous, store.findById(previous.getId()).orElseThrow());
    }

    private void operate(String operation, String token) {
        switch (operation) {
            case "rotate" -> service.rotate(token, fingerprint);
            case "validate" -> service.validateAndGetUsername(token);
            case "list" -> service.getActiveSessions(token);
            case "revoke" -> service.revokeSession(token, 7L);
            default -> throw new AssertionError("Unknown fixture operation");
        }
    }

    private RefreshSession seed(String token, String user, Instant expires) throws Exception {
        return store.save(RefreshSession.builder().username(user).tokenHash(digest(token)).createdAt(Instant.now().minusSeconds(7200))
                .expiresAt(expires).ip(fingerprint.ip()).userAgent(fingerprint.userAgent()).build());
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
