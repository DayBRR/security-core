package com.davidrr.security.spring.account;

import com.davidrr.security.jwt.JwtAuthenticationFilter;
import jakarta.servlet.Filter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import java.util.*;

/** Local structural validation only. The consumer supplies the complete live servlet inventory,
 * invokes this before traffic, and proves matchers, Null repositories and custom filter semantics.
 * This does not discover undeclared registrations or audit all chains (SEC-001-06).
 */
public final class AuthoritativeBearerComposition {
    private AuthoritativeBearerComposition() {}
    public static void validate(SecurityFilterChain authoritativeChain, Collection<? extends Filter> standaloneFilters) {
        Objects.requireNonNull(authoritativeChain, "authoritativeChain");
        Objects.requireNonNull(standaloneFilters, "standaloneFilters");
        List<Filter> filters = List.copyOf(authoritativeChain.getFilters());
        int bearer = unique(filters, AuthoritativeBearerFilter.class);
        int context = unique(filters, SecurityContextHolderFilter.class);
        int anonymous = unique(filters, AnonymousAuthenticationFilter.class);
        int authorization = unique(filters, AuthorizationFilter.class);
        if (!(context < bearer && bearer < anonymous && anonymous < authorization)) throw invalid();
        for (Filter filter : filters) if (alternative(filter)) throw invalid();
        for (Filter filter : standaloneFilters) {
            if (filter == null || filter instanceof AuthoritativeBearerFilter || alternative(filter)) throw invalid();
        }
    }
    private static int unique(List<Filter> filters, Class<? extends Filter> type) {
        int result = -1;
        for (int i = 0; i < filters.size(); i++) if (type.isInstance(filters.get(i))) {
            if (result != -1) throw invalid();
            result = i;
        }
        if (result == -1) throw invalid();
        return result;
    }
    private static boolean alternative(Filter filter) {
        return filter instanceof JwtAuthenticationFilter || filter instanceof BasicAuthenticationFilter
                || filter instanceof AbstractAuthenticationProcessingFilter || filter instanceof AuthenticationFilter
                || filter instanceof AbstractPreAuthenticatedProcessingFilter || filter instanceof RememberMeAuthenticationFilter
                || filter instanceof SecurityContextPersistenceFilter
                || filter.getClass().getName().equals("org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter");
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid authoritative bearer composition"); }
}
