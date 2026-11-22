package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.AccountSecuritySnapshot;
import java.time.Instant;

/** Verified signature and authoritative state for this acceptance, not a reusable emission lease. */
public final class VerifiedAccessIdentity {
    private final AccountSecuritySnapshot snapshot;
    private final String securityContextId;
    private final Instant tokenExpiresAt;
    VerifiedAccessIdentity(AccountSecuritySnapshot snapshot, String securityContextId, Instant tokenExpiresAt) {
        this.snapshot = snapshot; this.securityContextId = securityContextId; this.tokenExpiresAt = tokenExpiresAt;
    }
    public AccountSecuritySnapshot snapshot() { return snapshot; }
    public String securityContextId() { return securityContextId; }
    public Instant tokenExpiresAt() { return tokenExpiresAt; }
    @Override public String toString() { return "VerifiedAccessIdentity[REDACTED]"; }
}
