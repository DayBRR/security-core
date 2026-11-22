package com.davidrr.security.spring.account;

import com.davidrr.security.account.SecurityIdentity;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Objects;

/** Local consumer mapping; it is not evidence of authentication by itself. */
public record MappedAccessPrincipal(SecurityIdentity identity, UserDetails principal) {
    public MappedAccessPrincipal {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(principal, "principal");
    }
    @Override public String toString() { return "MappedAccessPrincipal[REDACTED]"; }
}
