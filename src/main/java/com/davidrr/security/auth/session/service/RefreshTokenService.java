package com.davidrr.security.auth.session.service;

import com.davidrr.security.auth.dto.RefreshRotationResult;
import com.davidrr.security.auth.dto.SessionFingerprint;
import com.davidrr.security.auth.dto.SessionResponse;
import com.davidrr.security.auth.session.model.RefreshSession;

import java.util.List;

public interface RefreshTokenService {

    String createRefreshToken(String username, SessionFingerprint fingerprint);

    String validateAndGetUsername(String refreshToken);

    RefreshRotationResult rotate(String currentRefreshToken, SessionFingerprint fingerprint);

    void revoke(String refreshToken);

    void revokeAll(String username);

    void cleanupExpired();

    RefreshSession findSessionByToken(String refreshToken);

    List<SessionResponse> getActiveSessions(String refreshToken);

    void revokeSession(String refreshToken, Long sessionId);
}