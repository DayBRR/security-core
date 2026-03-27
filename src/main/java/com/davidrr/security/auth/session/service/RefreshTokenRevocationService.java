package com.davidrr.security.auth.session.service;

public interface RefreshTokenRevocationService {

    void revokeAllActiveTokens(String username, String reason);
}