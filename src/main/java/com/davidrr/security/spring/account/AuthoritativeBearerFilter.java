package com.davidrr.security.spring.account;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;
import java.io.IOException;
import java.util.*;

/** Explicit chain installation only. Each dispatch is a new acceptance, never a session lookup. */
public final class AuthoritativeBearerFilter extends GenericFilterBean {
    private final ProviderManager manager;
    private final AccountAuthenticationFailureHandler failures;
    private final RequestMatcher bearerRequests;
    // Only contexts installed by this invocation stack may be restored after a nested dispatch.
    private final ThreadLocal<SecurityContext> active = new ThreadLocal<>();

    public AuthoritativeBearerFilter(AccountAccessAuthenticationProvider provider,
                                     AccountAuthenticationFailureHandler failures, RequestMatcher bearerRequests) {
        manager = new ProviderManager(List.of(Objects.requireNonNull(provider)));
        this.failures = Objects.requireNonNull(failures);
        this.bearerRequests = Objects.requireNonNull(bearerRequests);
    }

    @Override public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse reply)) {
            throw new ServletException("HTTP channel required");
        }
        DispatcherType type = request.getDispatcherType();
        SecurityContext outer = (type == DispatcherType.FORWARD || type == DispatcherType.INCLUDE) ? active.get() : null;
        active.remove();
        SecurityContextHolder.clearContext();
        AccountAccessAuthenticationToken input = null;
        try {
            if (type == DispatcherType.ERROR) {
                failures.writeUnexpectedFailure(http, reply);
                return;
            }
            final boolean inAuthoritativeSegment;
            try {
                inAuthoritativeSegment = bearerRequests.matches(http);
            } catch (RuntimeException matcherFailure) {
                if (type == DispatcherType.INCLUDE) throw new ServletException("Included request failed");
                failures.writeUnexpectedFailure(http, reply);
                return;
            }
            if (!inAuthoritativeSegment) {
                // Invocation means this chain was selected. A matcher gap is a broken
                // authoritative composition, not permission to try another mechanism.
                if (type == DispatcherType.INCLUDE) throw new ServletException("Included request denied");
                failures.write(http, reply, new AuthoritativeAuthenticationServiceException());
                return;
            }
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            try {
                String compact = resolve(http);
                if (compact != null) {
                    input = new AccountAccessAuthenticationToken(compact);
                    context.setAuthentication(manager.authenticate(input));
                }
            } catch (AuthenticationException failure) {
                if (type == DispatcherType.INCLUDE) throw new ServletException("Included request denied");
                failures.write(http, reply, failure);
                return;
            } catch (RuntimeException failure) {
                if (type == DispatcherType.INCLUDE) throw new ServletException("Included request failed");
                failures.writeUnexpectedFailure(http, reply);
                return;
            } finally {
                if (input != null) input.eraseCredentials();
            }
            SecurityContextHolder.setContext(context);
            active.set(context);
            // Deliberately outside the authentication catch: business exceptions are not credentials.
            try {
                chain.doFilter(request, response);
            } catch (IOException failure) {
                if (type == DispatcherType.INCLUDE) throw new ServletException("Included request failed");
                throw failure;
            }
        } finally {
            if (input != null) input.eraseCredentials();
            SecurityContextHolder.clearContext();
            active.remove();
            if (outer != null) {
                active.set(outer);
                SecurityContextHolder.setContext(outer);
            }
        }
    }

    private static String resolve(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        if (headers == null || !headers.hasMoreElements()) return null;
        String value = headers.nextElement();
        if (headers.hasMoreElements() || value == null || value.length() <= 7 || value.length() > 8199
                || !value.regionMatches(true, 0, "Bearer ", 0, 7)) throw invalid();
        String compact = value.substring(7);
        for (int i = 0; i < compact.length(); i++) {
            char c = compact.charAt(i);
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.')) throw invalid();
        }
        return compact;
    }
    private static BadCredentialsException invalid() { return new BadCredentialsException("Invalid bearer credential"); }
}
