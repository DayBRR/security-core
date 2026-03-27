package com.davidrr.security.auth.dto;

public record SessionFingerprint(
        String ip,
        String userAgent
) {
}
