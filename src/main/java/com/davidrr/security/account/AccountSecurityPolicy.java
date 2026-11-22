package com.davidrr.security.account;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

public record AccountSecurityPolicy(String securityContextId, Set<String> acceptedNamespaces, Duration lookupTimeout) {
    public AccountSecurityPolicy {
        SecurityIdentity.requireText(securityContextId, 128);
        acceptedNamespaces = Set.copyOf(acceptedNamespaces);
        if (acceptedNamespaces.isEmpty()) throw new IllegalArgumentException("Namespaces required");
        for (String namespace : acceptedNamespaces) new SecurityIdentity(namespace, "validation");
        Objects.requireNonNull(lookupTimeout, "lookupTimeout");
        try {
            long nanos = lookupTimeout.toNanos();
            if (nanos <= 0 || nanos > Long.MAX_VALUE / 4) throw new IllegalArgumentException("Invalid lookup budget");
        } catch (ArithmeticException overflow) { throw new IllegalArgumentException("Invalid lookup budget"); }
    }
    @Override public String toString() { return "AccountSecurityPolicy[REDACTED]"; }
}
