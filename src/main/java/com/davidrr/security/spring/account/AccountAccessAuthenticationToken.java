package com.davidrr.security.spring.account;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;

/** Input and successful result are separate instances. No public credential accessor. */
public final class AccountAccessAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;
    private transient String compactToken;
    private final UserDetails principal;

    public AccountAccessAuthenticationToken(String compactToken) {
        super(List.of());
        this.compactToken = compactToken;
        this.principal = null;
    }

    AccountAccessAuthenticationToken(UserDetails principal, Collection<? extends GrantedAuthority> authorities) {
        super(List.copyOf(authorities));
        this.principal = java.util.Objects.requireNonNull(principal);
        super.setAuthenticated(true);
    }

    String compactToken() { return compactToken; }
    @Override public Object getPrincipal() { return principal; }
    @Override public Object getCredentials() { return null; }
    @Override public void eraseCredentials() { compactToken = null; }
    @Override public void setAuthenticated(boolean authenticated) {
        if (authenticated) throw new IllegalArgumentException("Provider authentication required");
        super.setAuthenticated(false);
    }
    @Override public String toString() { return "AccountAccessAuthenticationToken[REDACTED]"; }
}
