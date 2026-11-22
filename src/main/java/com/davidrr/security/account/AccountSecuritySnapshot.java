package com.davidrr.security.account;

import java.util.Objects;
import java.util.Set;

/** One coherent authoritative read; contains no credentials or persistence entities. */
public record AccountSecuritySnapshot(SecurityIdentity identity, AdmissionState admission,
                                      SecurityRevision revision, String principalName, Set<String> authorities) {
    public AccountSecuritySnapshot {
        Objects.requireNonNull(identity, "identity"); Objects.requireNonNull(admission, "admission");
        Objects.requireNonNull(revision, "revision"); SecurityIdentity.requireText(principalName, 1024);
        authorities = Set.copyOf(authorities);
        for (String authority : authorities) SecurityIdentity.requireText(authority, 1024);
    }
    @Override public String toString() { return "AccountSecuritySnapshot[REDACTED]"; }
}
