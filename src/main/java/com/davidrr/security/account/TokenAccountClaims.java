package com.davidrr.security.account;

import java.util.Objects;

/** Decoded identity/revision, not by itself evidence of a verified signature. */
public record TokenAccountClaims(SecurityIdentity identity, SecurityRevision revision) {
    public TokenAccountClaims { Objects.requireNonNull(identity, "identity"); Objects.requireNonNull(revision, "revision"); }
    @Override public String toString() { return "TokenAccountClaims[REDACTED]"; }
}
