package com.davidrr.security.auth.dto;

public record AuthTokens(String accessToken, String refreshToken) {
    @Override
    public final String toString() {
        return "AuthTokens[REDACTED]";
    }
}
