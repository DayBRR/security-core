package com.davidrr.security.auth.dto;


public record RefreshRotationResult(
        String username,
        String refreshToken
) {
    @Override
    public final String toString() {
        return "RefreshRotationResult[REDACTED]";
    }
}
