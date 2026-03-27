package com.davidrr.security.auth.session.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class RefreshSession {

    private Long id;

    private String username;

    private String tokenHash;

    private Instant createdAt;
    private Instant expiresAt;
    private Instant lastUsedAt;

    private boolean revoked;
    private Instant revokedAt;
    private String revocationReason;

    private String replacedByTokenHash;

    private String ip;
    private String userAgent;
}