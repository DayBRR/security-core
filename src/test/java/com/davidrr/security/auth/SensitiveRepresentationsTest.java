package com.davidrr.security.auth;

import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.session.model.RefreshSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveRepresentationsTest {
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"synthetic-secret-SEC001", "usuario-\u00f1-\u79d8\u5bc6", "synthetic\r\nforged=value", "eySynthetic.payload.signature"})
    void allSevenTypesRedactRegardlessOfValues(String value) {
        RegisterRequest registration = new RegisterRequest();
        registration.setUsername(value);
        registration.setEmail(value);
        registration.setPassword(value);
        RefreshSession.RefreshSessionBuilder builder = RefreshSession.builder()
                .id(9023L).username(value).tokenHash(value)
                .createdAt(Instant.parse("2026-01-01T00:00:00Z"))
                .expiresAt(Instant.parse("2026-01-02T00:00:00Z"))
                .lastUsedAt(Instant.parse("2026-01-01T01:00:00Z"))
                .revoked(true).revokedAt(Instant.parse("2026-01-01T02:00:00Z"))
                .revocationReason(value).replacedByTokenHash(value).ip(value).userAgent(value);

        assertRepresentation(new AuthRequest(value, value), "AuthRequest");
        assertRepresentation(registration, "RegisterRequest");
        assertRepresentation(new AuthResponse(value), "AuthResponse");
        assertRepresentation(new AuthTokens(value, value), "AuthTokens");
        assertRepresentation(new RefreshRotationResult(value, value), "RefreshRotationResult");
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        assertRepresentation(builder.build(), "RefreshSession");
    }

    @Test
    void builderRedactsEmptyPartialCompleteAndReusedStatesWithoutChangingData() {
        RefreshSession.RefreshSessionBuilder builder = RefreshSession.builder();
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        assertRepresentation(builder.build(), "RefreshSession");
        builder.username("synthetic-user-SEC001");
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        builder.id(9023L).tokenHash("synthetic-hash-current-SEC001")
                .createdAt(created).expiresAt(created.plusSeconds(86400))
                .lastUsedAt(created.plusSeconds(60)).revoked(true)
                .revokedAt(created.plusSeconds(120)).revocationReason("synthetic-reason-SEC001")
                .replacedByTokenHash("synthetic-hash-next-SEC001")
                .ip("192.0.2.23").userAgent("synthetic-agent-SEC001");
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        RefreshSession session = builder.build();
        assertRepresentation(session, "RefreshSession");
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        assertAll(
                () -> assertEquals(9023L, session.getId()),
                () -> assertEquals("synthetic-user-SEC001", session.getUsername()),
                () -> assertEquals("synthetic-hash-current-SEC001", session.getTokenHash()),
                () -> assertEquals(created, session.getCreatedAt()),
                () -> assertEquals(created.plusSeconds(86400), session.getExpiresAt()),
                () -> assertEquals(created.plusSeconds(60), session.getLastUsedAt()),
                () -> assertTrue(session.isRevoked()),
                () -> assertEquals(created.plusSeconds(120), session.getRevokedAt()),
                () -> assertEquals("synthetic-reason-SEC001", session.getRevocationReason()),
                () -> assertEquals("synthetic-hash-next-SEC001", session.getReplacedByTokenHash()),
                () -> assertEquals("192.0.2.23", session.getIp()),
                () -> assertEquals("synthetic-agent-SEC001", session.getUserAgent()));
        builder.tokenHash("synthetic-hash-reused-builder");
        assertRepresentation(builder, "RefreshSession.RefreshSessionBuilder");
        assertEquals("synthetic-hash-reused-builder", builder.build().getTokenHash());
        assertEquals("synthetic-hash-current-SEC001", session.getTokenHash());
    }

    @Test
    void requestSettersAndTokenAccessorsRemainIntactAfterRendering() {
        AuthRequest request = new AuthRequest();
        request.setUsername("synthetic-user-SEC001");
        request.setPassword("synthetic-password-SEC001");
        assertRepresentation(request, "AuthRequest");
        request.setPassword("synthetic-new-password-SEC001");
        assertRepresentation(request, "AuthRequest");
        assertEquals("synthetic-user-SEC001", request.getUsername());
        assertEquals("synthetic-new-password-SEC001", request.getPassword());
        AuthResponse response = new AuthResponse("synthetic-access-SEC001");
        AuthTokens tokens = new AuthTokens("synthetic-access-SEC001", "synthetic-refresh-SEC001");
        RefreshRotationResult rotation = new RefreshRotationResult("synthetic-user-SEC001", "synthetic-refresh-SEC001");
        assertRepresentation(response, "AuthResponse");
        assertRepresentation(tokens, "AuthTokens");
        assertRepresentation(rotation, "RefreshRotationResult");
        assertEquals("synthetic-access-SEC001", response.getToken());
        assertEquals("synthetic-access-SEC001", tokens.accessToken());
        assertEquals("synthetic-refresh-SEC001", tokens.refreshToken());
        assertEquals("synthetic-user-SEC001", rotation.username());
        assertEquals("synthetic-refresh-SEC001", rotation.refreshToken());
    }

    private static void assertRepresentation(Object value, String type) {
        String expected = type + "[REDACTED]";
        assertEquals(expected, value.toString());
        assertEquals(expected, String.valueOf(value));
        assertEquals(expected, "" + value);
        assertEquals(expected, String.format("%s", value));
    }
}
