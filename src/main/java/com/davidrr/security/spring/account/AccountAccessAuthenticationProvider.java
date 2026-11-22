package com.davidrr.security.spring.account;

import com.davidrr.security.account.AccountSecuritySnapshot;
import com.davidrr.security.account.SecurityValidationException;
import com.davidrr.security.jwt.authoritative.AuthoritativeAccessTokenVerifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.time.Clock;
import java.util.*;

/** Dedicated access-v1 provider. The mapper and authoritative adapter are trusted consumer code. */
public final class AccountAccessAuthenticationProvider implements AuthenticationProvider {
    private final AuthoritativeAccessTokenVerifier verifier;
    private final AccessPrincipalMapper principals;
    private final Clock clock;

    public AccountAccessAuthenticationProvider(AuthoritativeAccessTokenVerifier verifier,
                                             AccessPrincipalMapper principals, Clock clock) {
        this.verifier = Objects.requireNonNull(verifier);
        this.principals = Objects.requireNonNull(principals);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override public boolean supports(Class<?> authentication) {
        return authentication == AccountAccessAuthenticationToken.class;
    }

    @Override public Authentication authenticate(Authentication authentication) {
        if (authentication == null || !supports(authentication.getClass())) return null;
        AccountAccessAuthenticationToken input = (AccountAccessAuthenticationToken) authentication;
        try {
            if (input.isAuthenticated() || input.compactToken() == null || input.compactToken().isEmpty()) throw invalid();
            var verified = verifier.verify(input.compactToken());
            AccountSecuritySnapshot snapshot = verified.snapshot();
            MappedAccessPrincipal mapped = principals.map(snapshot);
            if (mapped == null || !snapshot.identity().equals(mapped.identity())) throw unavailable();
            UserDetails principal = mapped.principal();
            validate(principal, snapshot);
            // Copy permission values rather than retaining mutable GrantedAuthority implementations.
            var authorities = snapshot.authorities().stream().sorted().map(SimpleGrantedAuthority::new).toList();
            validate(principal, snapshot);
            if (!verified.tokenExpiresAt().isAfter(clock.instant())) throw invalid();
            return new AccountAccessAuthenticationToken(principal, authorities);
        } catch (SecurityValidationException failure) {
            throw switch (failure.failure()) {
                case DEPENDENCY_UNAVAILABLE, CONTRACT_VIOLATION -> unavailable();
                case TOKEN_INVALID, IDENTITY_ABSENT, ACCOUNT_NOT_ADMITTED, REVISION_MISMATCH -> invalid();
            };
        } finally {
            input.eraseCredentials();
        }
    }

    private static void validate(UserDetails principal, AccountSecuritySnapshot snapshot) {
        if (principal == null || !snapshot.principalName().equals(principal.getUsername())
                || !principal.isEnabled() || !principal.isAccountNonLocked()
                || !principal.isAccountNonExpired() || !principal.isCredentialsNonExpired()) throw unavailable();
        String password = principal.getPassword();
        if (password != null && !password.isEmpty()) throw unavailable();
        var granted = principal.getAuthorities();
        if (granted == null) throw unavailable();
        Set<String> values = new HashSet<>();
        for (var authority : granted) {
            if (authority == null || authority.getAuthority() == null || authority.getAuthority().isEmpty()
                    || !values.add(authority.getAuthority())) throw unavailable();
        }
        if (!values.equals(snapshot.authorities())) throw unavailable();
    }
    private static BadCredentialsException invalid() { return new BadCredentialsException("Invalid bearer credential"); }
    private static AuthoritativeAuthenticationServiceException unavailable() { return new AuthoritativeAuthenticationServiceException(); }
}
