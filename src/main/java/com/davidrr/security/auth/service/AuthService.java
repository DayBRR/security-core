package com.davidrr.security.auth.service;

import com.davidrr.security.auth.dto.*;
import java.util.List;

public interface AuthService {

    AuthTokens register(RegisterRequest request, SessionFingerprint fingerprint);

    AuthTokens login(AuthRequest request, SessionFingerprint fingerprint);

    AuthTokens refresh(String refreshToken, SessionFingerprint fingerprint);

    void logout(String refreshToken);

    void logoutAll(String refreshToken);

    List<SessionResponse> getSessions(String refreshToken);

    void revokeSession(String refreshToken, Long sessionId);
}