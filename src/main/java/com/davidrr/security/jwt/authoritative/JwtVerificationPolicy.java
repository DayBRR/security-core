package com.davidrr.security.jwt.authoritative;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

public record JwtVerificationPolicy(String securityContextId, String issuer, Set<String> audiences,
                                    Set<String> algorithms, Duration clockSkew, Duration maxTokenLifetime,
                                    JwtReadLimits readLimits) {
    public JwtVerificationPolicy {
        if (securityContextId == null || securityContextId.isBlank() || securityContextId.length() > 128
                || securityContextId.chars().anyMatch(Character::isISOControl)
                || issuer == null || issuer.isBlank() || issuer.length() > 1024
                || issuer.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Invalid JWT context");
        audiences = Set.copyOf(audiences); algorithms = Set.copyOf(algorithms);
        if (audiences.isEmpty() || audiences.stream().anyMatch(a -> a.isBlank() || a.length() > 1024
                || a.chars().anyMatch(Character::isISOControl)) || !algorithms.equals(Set.of("HS256"))) {
            throw new IllegalArgumentException("Invalid access-v1 destination or algorithm");
        }
        Objects.requireNonNull(clockSkew); Objects.requireNonNull(maxTokenLifetime); Objects.requireNonNull(readLimits);
        if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofSeconds(60)) > 0
                || maxTokenLifetime.isNegative() || maxTokenLifetime.isZero()
                || maxTokenLifetime.compareTo(Duration.ofSeconds(253402300799L)) > 0) throw new IllegalArgumentException("Invalid JWT time policy");
    }
    @Override public String toString() { return "JwtVerificationPolicy[REDACTED]"; }
}
