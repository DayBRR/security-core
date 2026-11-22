package com.davidrr.security.jwt.authoritative;

import java.util.Map;

/** Created only after JWS and access-v1 validation. Contains immutable scalar JSON values. */
public final class VerifiedJwtClaims {
    private final Map<String, Object> claims;
    private final String securityContextId;
    VerifiedJwtClaims(Map<String, Object> claims, String securityContextId) {
        this.claims = Map.copyOf(claims); this.securityContextId = securityContextId;
    }
    public Map<String, Object> claims() { return claims; }
    public String securityContextId() { return securityContextId; }
    @Override public String toString() { return "VerifiedJwtClaims[REDACTED]"; }
}
