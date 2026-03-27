package com.davidrr.security.auth.dto;

import java.time.Instant;

public record SessionResponse(
        Long id,
        Instant createdAt,
        Instant lastUsedAt,
        Instant expiresAt,
        String ip,
        String userAgent,
        String device,
        boolean current
) {}