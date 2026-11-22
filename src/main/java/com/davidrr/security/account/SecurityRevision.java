package com.davidrr.security.account;

/** Opaque security generation. Scheme-specific canonicalization belongs to the codec. */
public record SecurityRevision(String scheme, String value) {
    public SecurityRevision {
        if (scheme == null || !scheme.matches("[A-Za-z0-9._:-]{1,128}")) throw new IllegalArgumentException("Invalid revision scheme");
        SecurityIdentity.requireText(value, 256);
    }
    @Override public String toString() { return "SecurityRevision[REDACTED]"; }
}
