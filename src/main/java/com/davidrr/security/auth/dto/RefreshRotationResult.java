package com.davidrr.security.auth.dto;


public record RefreshRotationResult(
        String username,
        String refreshToken
) {
}
