package com.davidrr.security.auth.session.service.impl;

import com.davidrr.security.audit.SecurityAuditContext;
import com.davidrr.security.audit.SecurityAuditService;
import com.davidrr.security.audit.SecurityEventType;
import com.davidrr.security.auth.dto.RefreshRotationResult;
import com.davidrr.security.auth.dto.SessionFingerprint;
import com.davidrr.security.auth.dto.SessionResponse;
import com.davidrr.security.auth.exception.RefreshTokenExpiredException;
import com.davidrr.security.auth.exception.RefreshTokenInvalidException;
import com.davidrr.security.auth.exception.RefreshTokenReuseException;
import com.davidrr.security.auth.exception.SessionNotFoundException;
import com.davidrr.security.auth.exception.SuspiciousSessionException;
import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import com.davidrr.security.auth.session.service.RefreshTokenRevocationService;
import com.davidrr.security.auth.session.service.RefreshTokenService;
import com.davidrr.security.auth.util.UserAgentUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    public static final String REASON_SUSPICIOUS_SESSION = "SUSPICIOUS_SESSION";

    private static final String REASON_ROTATED = "ROTATED";
    private static final String REASON_LOGOUT = "LOGOUT";
    private static final String REASON_LOGOUT_ALL = "LOGOUT_ALL";
    private static final String REASON_REUSE_DETECTED = "REUSE_DETECTED";
    private static final String REASON_EXPIRED = "EXPIRED";
    private static final String REASON_SESSION_REVOKED = "SESSION_REVOKED";
    private static final String REASON_INVALID_TOKEN = "INVALID_TOKEN";
    private static final String REASON_SESSION_ACCESS = "SESSION_ACCESS";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private final RefreshTokenRevocationService refreshTokenRevocationService;
    private final RefreshSessionStore refreshSessionStore;
    private final SecurityAuditService securityAuditService;

    @Value("${security.refresh.expiration-days:14}")
    private long refreshExpirationDays;

    @Override
    @Transactional
    public String createRefreshToken(String username, SessionFingerprint fingerprint) {
        String tokenPlain = generateTokenPlain();
        String tokenHash = sha256Hex(tokenPlain);
        Instant now = Instant.now();

        RefreshSession session = RefreshSession.builder()
                .username(username)
                .tokenHash(tokenHash)
                .createdAt(now)
                .expiresAt(now.plus(Duration.ofDays(refreshExpirationDays)))
                .revoked(false)
                .lastUsedAt(null)
                .revokedAt(null)
                .revocationReason(null)
                .replacedByTokenHash(null)
                .ip(fingerprint.ip())
                .userAgent(fingerprint.userAgent())
                .build();

        RefreshSession saved = refreshSessionStore.save(session);

        securityAuditService.log(
                SecurityEventType.REFRESH_TOKEN_CREATED,
                SecurityAuditContext.of(
                        username,
                        fingerprint.ip(),
                        fingerprint.userAgent(),
                        saved.getId(),
                        null,
                        "Refresh token created"
                )
        );

        return tokenPlain;
    }

    @Override
    @Transactional
    public String validateAndGetUsername(String refreshToken) {
        RefreshSession session = requireValidSession(refreshToken, null, "validation");
        session.setLastUsedAt(Instant.now());
        refreshSessionStore.save(session);
        return session.getUsername();
    }

    @Override
    @Transactional
    public RefreshRotationResult rotate(String currentRefreshToken, SessionFingerprint fingerprint) {
        if (currentRefreshToken == null || currentRefreshToken.isBlank()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            fingerprint != null ? fingerprint.ip() : null,
                            fingerprint != null ? fingerprint.userAgent() : null,
                            null,
                            REASON_INVALID_TOKEN,
                            "Refresh token is null or blank"
                    )
            );
            throw new RefreshTokenInvalidException();
        }

        String currentTokenHash = sha256Hex(currentRefreshToken);

        RefreshSession currentSession = refreshSessionStore.findByTokenHash(currentTokenHash)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.REFRESH_INVALID_TOKEN,
                            SecurityAuditContext.of(
                                    null,
                                    fingerprint != null ? fingerprint.ip() : null,
                                    fingerprint != null ? fingerprint.userAgent() : null,
                                    null,
                                    REASON_INVALID_TOKEN,
                                    "Refresh token not found during rotation"
                            )
                    );
                    return new RefreshTokenInvalidException();
                });

        Instant now = Instant.now();

        if (currentSession.isRevoked()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_REUSE_DETECTED,
                            "Refresh token reuse detected during rotation"
                    )
            );

            refreshTokenRevocationService.revokeAllActiveTokens(
                    currentSession.getUsername(),
                    REASON_REUSE_DETECTED
            );
            throw new RefreshTokenReuseException();
        }

        if (currentSession.getExpiresAt().isBefore(now)) {
            currentSession.setRevoked(true);
            currentSession.setRevokedAt(now);
            currentSession.setRevocationReason(REASON_EXPIRED);
            currentSession.setLastUsedAt(now);
            refreshSessionStore.save(currentSession);

            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_EXPIRED,
                            "Refresh token expired during rotation"
                    )
            );

            throw new RefreshTokenExpiredException();
        }

        if (currentSession.getUserAgent() != null
                && fingerprint.userAgent() != null
                && !currentSession.getUserAgent().equals(fingerprint.userAgent())) {

            securityAuditService.log(
                    SecurityEventType.SUSPICIOUS_SESSION_DETECTED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            currentSession.getId(),
                            REASON_SUSPICIOUS_SESSION,
                            "User-Agent mismatch detected during refresh rotation"
                    )
            );

            refreshTokenRevocationService.revokeAllActiveTokens(
                    currentSession.getUsername(),
                    REASON_SUSPICIOUS_SESSION
            );
            throw new SuspiciousSessionException();
        }

        String newTokenPlain = generateTokenPlain();
        String newTokenHash = sha256Hex(newTokenPlain);

        RefreshSession newSession = RefreshSession.builder()
                .username(currentSession.getUsername())
                .tokenHash(newTokenHash)
                .createdAt(now)
                .expiresAt(now.plus(Duration.ofDays(refreshExpirationDays)))
                .revoked(false)
                .lastUsedAt(null)
                .revokedAt(null)
                .revocationReason(null)
                .replacedByTokenHash(null)
                .ip(currentSession.getIp())
                .userAgent(currentSession.getUserAgent())
                .build();

        currentSession.setRevoked(true);
        currentSession.setRevokedAt(now);
        currentSession.setRevocationReason(REASON_ROTATED);
        currentSession.setLastUsedAt(now);
        currentSession.setReplacedByTokenHash(newTokenHash);

        refreshSessionStore.save(currentSession);
        RefreshSession savedNewSession = refreshSessionStore.save(newSession);

        securityAuditService.log(
                SecurityEventType.REFRESH_TOKEN_ROTATED,
                SecurityAuditContext.of(
                        currentSession.getUsername(),
                        currentSession.getIp(),
                        currentSession.getUserAgent(),
                        savedNewSession.getId(),
                        REASON_ROTATED,
                        "Refresh token rotated successfully"
                )
        );

        return new RefreshRotationResult(currentSession.getUsername(), newTokenPlain);
    }

    @Override
    @Transactional
    public void revoke(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }

        String tokenHash = sha256Hex(refreshToken);
        Instant now = Instant.now();

        refreshSessionStore.findByTokenHash(tokenHash).ifPresent(session -> {
            if (!session.isRevoked()) {
                session.setRevoked(true);
                session.setRevokedAt(now);
                session.setRevocationReason(REASON_LOGOUT);
                refreshSessionStore.save(session);

                securityAuditService.log(
                        SecurityEventType.LOGOUT,
                        SecurityAuditContext.of(
                                session.getUsername(),
                                session.getIp(),
                                session.getUserAgent(),
                                session.getId(),
                                REASON_LOGOUT,
                                "Current session logged out"
                        )
                );
            }
        });
    }

    @Override
    @Transactional
    public void revokeAll(String username) {
        securityAuditService.log(
                SecurityEventType.LOGOUT_ALL,
                SecurityAuditContext.of(
                        username,
                        null,
                        null,
                        null,
                        REASON_LOGOUT_ALL,
                        "All active sessions revoked by user"
                )
        );

        refreshTokenRevocationService.revokeAllActiveTokens(username, REASON_LOGOUT_ALL);
    }

    @Override
    @Transactional
    public void cleanupExpired() {
        Instant now = Instant.now();

        List<RefreshSession> expiredActiveSessions = refreshSessionStore.findExpiredActiveSessions(now);

        for (RefreshSession session : expiredActiveSessions) {
            session.setRevoked(true);
            session.setRevokedAt(now);
            session.setRevocationReason(REASON_EXPIRED);

            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            session.getUsername(),
                            session.getIp(),
                            session.getUserAgent(),
                            session.getId(),
                            REASON_EXPIRED,
                            "Expired refresh token cleaned up"
                    )
            );
        }

        refreshSessionStore.saveAll(expiredActiveSessions);
    }

    @Override
    @Transactional(readOnly = true)
    public RefreshSession findSessionByToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            null,
                            null,
                            null,
                            REASON_INVALID_TOKEN,
                            "Refresh token is null or blank"
                    )
            );
            throw new RefreshTokenInvalidException();
        }

        String tokenHash = sha256Hex(refreshToken);

        return refreshSessionStore.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.REFRESH_INVALID_TOKEN,
                            SecurityAuditContext.of(
                                    null,
                                    null,
                                    null,
                                    null,
                                    REASON_INVALID_TOKEN,
                                    "Refresh token not found"
                            )
                    );
                    return new RefreshTokenInvalidException();
                });
    }

    @Override
    @Transactional(readOnly = true)
    public List<SessionResponse> getActiveSessions(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            null,
                            null,
                            null,
                            REASON_INVALID_TOKEN,
                            "Refresh token is null or blank when listing sessions"
                    )
            );
            throw new RefreshTokenInvalidException();
        }

        String currentTokenHash = sha256Hex(refreshToken);

        RefreshSession currentSession = refreshSessionStore.findByTokenHash(currentTokenHash)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.REFRESH_INVALID_TOKEN,
                            SecurityAuditContext.of(
                                    null,
                                    null,
                                    null,
                                    null,
                                    REASON_INVALID_TOKEN,
                                    "Refresh token not found when listing sessions"
                            )
                    );
                    return new RefreshTokenInvalidException();
                });

        if (currentSession.isRevoked()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_REUSE_DETECTED,
                            "Revoked refresh token used when listing sessions"
                    )
            );
            throw new RefreshTokenReuseException();
        }

        if (currentSession.getExpiresAt().isBefore(Instant.now())) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_EXPIRED,
                            "Expired refresh token used when listing sessions"
                    )
            );
            throw new RefreshTokenExpiredException();
        }

        List<RefreshSession> sessions =
                refreshSessionStore.findActiveByUsernameOrderByCreatedAtDesc(currentSession.getUsername());

        securityAuditService.log(
                SecurityEventType.SESSIONS_LISTED,
                SecurityAuditContext.of(
                        currentSession.getUsername(),
                        currentSession.getIp(),
                        currentSession.getUserAgent(),
                        currentSession.getId(),
                        REASON_SESSION_ACCESS,
                        "Active sessions listed"
                )
        );

        return sessions.stream()
                .map(session -> new SessionResponse(
                        session.getId(),
                        session.getCreatedAt(),
                        session.getLastUsedAt(),
                        session.getExpiresAt(),
                        session.getIp(),
                        session.getUserAgent(),
                        UserAgentUtils.toDeviceLabel(session.getUserAgent()),
                        session.getTokenHash().equals(currentTokenHash)
                ))
                .toList();
    }

    @Override
    @Transactional
    public void revokeSession(String refreshToken, Long sessionId) {
        if (refreshToken == null || refreshToken.isBlank()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            null,
                            null,
                            null,
                            REASON_INVALID_TOKEN,
                            "Refresh token is null or blank when revoking session"
                    )
            );
            throw new RefreshTokenInvalidException();
        }

        String currentTokenHash = sha256Hex(refreshToken);

        RefreshSession currentSession = refreshSessionStore.findByTokenHash(currentTokenHash)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.REFRESH_INVALID_TOKEN,
                            SecurityAuditContext.of(
                                    null,
                                    null,
                                    null,
                                    null,
                                    REASON_INVALID_TOKEN,
                                    "Refresh token not found when revoking session"
                            )
                    );
                    return new RefreshTokenInvalidException();
                });

        Instant now = Instant.now();

        if (currentSession.isRevoked()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_REUSE_DETECTED,
                            "Revoked refresh token used when revoking session"
                    )
            );

            refreshTokenRevocationService.revokeAllActiveTokens(
                    currentSession.getUsername(),
                    REASON_REUSE_DETECTED
            );
            throw new RefreshTokenReuseException();
        }

        if (currentSession.getExpiresAt().isBefore(now)) {
            currentSession.setRevoked(true);
            currentSession.setRevokedAt(now);
            currentSession.setRevocationReason(REASON_EXPIRED);
            refreshSessionStore.save(currentSession);

            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            currentSession.getId(),
                            REASON_EXPIRED,
                            "Expired refresh token used when revoking session"
                    )
            );

            throw new RefreshTokenExpiredException();
        }

        RefreshSession targetSession = refreshSessionStore.findById(sessionId)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.SESSION_REVOKE_DENIED,
                            SecurityAuditContext.of(
                                    currentSession.getUsername(),
                                    currentSession.getIp(),
                                    currentSession.getUserAgent(),
                                    sessionId,
                                    REASON_SESSION_REVOKED,
                                    "Target session not found"
                            )
                    );
                    return new SessionNotFoundException();
                });

        if (!targetSession.getUsername().equals(currentSession.getUsername())) {
            securityAuditService.log(
                    SecurityEventType.SESSION_REVOKE_DENIED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            currentSession.getIp(),
                            currentSession.getUserAgent(),
                            targetSession.getId(),
                            REASON_SESSION_REVOKED,
                            "Attempt to revoke session that belongs to another user"
                    )
            );
            throw new SessionNotFoundException();
        }

        if (!targetSession.isRevoked()) {
            targetSession.setRevoked(true);
            targetSession.setRevokedAt(now);
            targetSession.setRevocationReason(REASON_SESSION_REVOKED);
            refreshSessionStore.save(targetSession);

            securityAuditService.log(
                    SecurityEventType.SESSION_REVOKED,
                    SecurityAuditContext.of(
                            currentSession.getUsername(),
                            targetSession.getIp(),
                            targetSession.getUserAgent(),
                            targetSession.getId(),
                            REASON_SESSION_REVOKED,
                            "Specific session revoked by user"
                    )
            );
        }
    }

    private RefreshSession requireValidSession(String refreshToken, SessionFingerprint fingerprint, String action) {
        if (refreshToken == null || refreshToken.isBlank()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            fingerprint != null ? fingerprint.ip() : null,
                            fingerprint != null ? fingerprint.userAgent() : null,
                            null,
                            REASON_INVALID_TOKEN,
                            "Refresh token is null or blank during " + action
                    )
            );
            throw new RefreshTokenInvalidException();
        }

        String tokenHash = sha256Hex(refreshToken);
        RefreshSession session = refreshSessionStore.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    securityAuditService.log(
                            SecurityEventType.REFRESH_INVALID_TOKEN,
                            SecurityAuditContext.of(
                                    null,
                                    fingerprint != null ? fingerprint.ip() : null,
                                    fingerprint != null ? fingerprint.userAgent() : null,
                                    null,
                                    REASON_INVALID_TOKEN,
                                    "Refresh token not found during " + action
                            )
                    );
                    return new RefreshTokenInvalidException();
                });

        Instant now = Instant.now();

        if (session.isRevoked()) {
            securityAuditService.log(
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    SecurityAuditContext.of(
                            session.getUsername(),
                            session.getIp(),
                            session.getUserAgent(),
                            session.getId(),
                            REASON_REUSE_DETECTED,
                            "Revoked refresh token used during " + action
                    )
            );

            refreshTokenRevocationService.revokeAllActiveTokens(
                    session.getUsername(),
                    REASON_REUSE_DETECTED
            );
            throw new RefreshTokenReuseException();
        }

        if (session.getExpiresAt().isBefore(now)) {
            session.setRevoked(true);
            session.setRevokedAt(now);
            session.setRevocationReason(REASON_EXPIRED);
            refreshSessionStore.save(session);

            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            session.getUsername(),
                            session.getIp(),
                            session.getUserAgent(),
                            session.getId(),
                            REASON_EXPIRED,
                            "Expired refresh token used during " + action
                    )
            );

            throw new RefreshTokenExpiredException();
        }

        return session;
    }

    private static String generateTokenPlain() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hashed);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}