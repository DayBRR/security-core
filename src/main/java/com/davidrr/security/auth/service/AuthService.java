package com.davidrr.security.auth.service;

import com.davidrr.security.auth.dto.AuthRequest;
import com.davidrr.security.auth.dto.AuthTokens;
import com.davidrr.security.auth.dto.SessionFingerprint;
import com.davidrr.security.auth.dto.SessionResponse;

import java.util.List;

public interface AuthService {

    AuthTokens login(AuthRequest request, SessionFingerprint fingerprint);

    AuthTokens refresh(String refreshToken, SessionFingerprint fingerprint);

    void logout(String refreshToken);

    void logoutAll(String refreshToken);

    List<SessionResponse> getSessions(String refreshToken);

    void revokeSession(String refreshToken, Long sessionId);
}
