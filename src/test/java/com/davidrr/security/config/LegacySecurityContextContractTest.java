package com.davidrr.security.config;

import com.davidrr.security.audit.SecurityAuditService;
import com.davidrr.security.auth.dto.SessionFingerprint;
import com.davidrr.security.auth.port.*;
import com.davidrr.security.auth.service.AuthService;
import com.davidrr.security.auth.service.impl.AuthServiceImpl;
import com.davidrr.security.auth.session.port.RefreshSessionStore;
import com.davidrr.security.auth.session.service.RefreshTokenService;
import com.davidrr.security.auth.session.service.impl.*;
import com.davidrr.security.common.*;
import com.davidrr.security.jwt.*;
import com.davidrr.security.ratelimit.config.*;
import com.davidrr.security.ratelimit.service.InMemoryRateLimiterService;
import com.davidrr.security.ratelimit.util.RateLimitKeyFactory;
import com.davidrr.security.support.InMemoryRefreshSessionStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.*;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.cors.*;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Explicit servlet composition only: no auto-config, real DB, transaction or server registration proof. */
class LegacySecurityContextContractTest {
    private static final byte[] KEY = "fixture0123456789fixture0123456789".getBytes(StandardCharsets.US_ASCII);
    private static final String SECRET = "security.jwt.secret-key=" + Base64.getEncoder().encodeToString(KEY);

    private WebApplicationContextRunner core() {
        return new WebApplicationContextRunner().withUserConfiguration(Fixture.class)
                .withBean(UserDetailsService.class, () -> name -> User.withUsername(name).password("encoded").authorities("FIXTURE").build())
                .withBean(UserRegistrationPort.class, () -> (name, email, encoded) -> new UserRegistrationPort.RegisteredUser(7L, name))
                .withBean(UserLoginAuditPort.class, () -> name -> { });
    }

    private WebApplicationContextRunner configured() {
        return core().withBean(UserProvider.class, () -> name -> User.withUsername(name).password("encoded").authorities("FIXTURE").build())
                .withPropertyValues(SECRET);
    }

    @Test
    void contextProvidesLegacyNamedBeansAndJwtPrecedesAnonymousAndAuthorization() {
        configured().run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(AuthService.class));
            assertInstanceOf(AuthenticationManager.class, context.getBean("authenticationManager"));
            PasswordEncoder encoder = context.getBean("passwordEncoder", PasswordEncoder.class);
            assertInstanceOf(BCryptPasswordEncoder.class, encoder);
            assertTrue(encoder.matches("synthetic-password", encoder.encode("synthetic-password")));
            assertNotNull(context.getBean("corsConfigurationSource", CorsConfigurationSource.class));
            List<Filter> filters = context.getBean("securityFilterChain", SecurityFilterChain.class).getFilters();
            int jwt = position(filters, JwtAuthenticationFilter.class);
            assertTrue(jwt < position(filters, AnonymousAuthenticationFilter.class));
            assertTrue(jwt < position(filters, AuthorizationFilter.class));
            assertEquals(1, filters.stream().filter(JwtAuthenticationFilter.class::isInstance).count());
            // No UsernamePasswordAuthenticationFilter is installed by this composition;
            // compare against authentication/authorization filters actually in its chain.
        });
    }

    @Test
    void indispensableUserProviderIsRequiredForFullLegacyComposition() {
        core().withPropertyValues(SECRET).run(context -> {
            assertNotNull(context.getStartupFailure());
            assertTrue(hasCause(context.getStartupFailure(), NoSuchBeanDefinitionException.class));
        });
    }

    @Test
    void missingJwtSecretPreventsStartup() {
        core().withBean(UserProvider.class, () -> name -> User.withUsername(name).password("encoded").authorities("FIXTURE").build())
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(hasCause(context.getStartupFailure(), IllegalArgumentException.class));
                });
    }

    @Test
    void weakJwtKeyPreventsStartup() {
        configured().withPropertyValues("security.jwt.secret-key=" + Base64.getEncoder().encodeToString(new byte[8]))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(hasCause(context.getStartupFailure(), WeakKeyException.class));
                });
    }

    @Test
    void legacyDefaultsBindWithTheirExistingUnits() {
        configured().run(context -> {
            assertNull(context.getStartupFailure());
            RateLimitProperties properties = context.getBean(RateLimitProperties.class);
            for (RateLimitProperties.Bucket bucket : List.of(properties.getLogin(), properties.getRefresh())) {
                assertTrue(bucket.isEnabled()); assertEquals(5, bucket.getMaxAttempts()); assertEquals(60, bucket.getWindowSeconds());
            }
            Claims claims = claims(context.getBean(JwtService.class).generateToken("alpha", List.of("FIXTURE")));
            assertNotNull(claims.getIssuer());
            assertEquals(900000L, claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
            RefreshTokenService refresh = context.getBean(RefreshTokenService.class);
            refresh.createRefreshToken("alpha", new SessionFingerprint("192.0.2.50", "synthetic-agent"));
            var stored = context.getBean(RefreshSessionStore.class).findActiveByUsername("alpha").get(0);
            assertEquals(Duration.ofDays(14), Duration.between(stored.getCreatedAt(), stored.getExpiresAt()));
            CorsConfiguration cors = context.getBean("corsConfigurationSource", CorsConfigurationSource.class)
                    .getCorsConfiguration(new MockHttpServletRequest("GET", "/fixture/private"));
            assertNotNull(cors);
            assertFalse(cors.getAllowedOrigins().isEmpty());
            assertTrue(cors.getAllowedMethods().contains("GET"));
            // Observed defaults are not universal deployment policy; request tests override origins explicitly.
        });
    }

    @Test
    void explicitOverridesBindJwtMillisecondsRefreshDaysRateLimitAndCors() {
        configured().withPropertyValues("security.jwt.issuer=fixture-issuer", "security.jwt.expiration=60000",
                "security.refresh.expiration-days=2", "security.rate-limit.login.max-attempts=3",
                "security.rate-limit.login.window-seconds=120", "security.rate-limit.refresh.enabled=false",
                "security.cors.allowed-origins=https://fixture.example", "security.cors.allowed-methods=GET,POST",
                "security.cors.allowed-headers=Authorization,X-Fixture", "security.cors.allow-credentials=false").run(context -> {
            assertNull(context.getStartupFailure());
            RateLimitProperties properties = context.getBean(RateLimitProperties.class);
            assertEquals(3, properties.getLogin().getMaxAttempts());
            assertEquals(120, properties.getLogin().getWindowSeconds());
            assertFalse(properties.getRefresh().isEnabled());
            Claims claims = claims(context.getBean(JwtService.class).generateToken("alpha", List.of()));
            assertEquals("fixture-issuer", claims.getIssuer());
            assertEquals(60000L, claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
            context.getBean(RefreshTokenService.class).createRefreshToken("alpha", new SessionFingerprint("192.0.2.50", "synthetic-agent"));
            var session = context.getBean(RefreshSessionStore.class).findActiveByUsername("alpha").get(0);
            assertEquals(Duration.ofDays(2), Duration.between(session.getCreatedAt(), session.getExpiresAt()));
            CorsConfiguration cors = context.getBean("corsConfigurationSource", CorsConfigurationSource.class)
                    .getCorsConfiguration(new MockHttpServletRequest("GET", "/fixture/private"));
            assertEquals(List.of("https://fixture.example"), cors.getAllowedOrigins());
            assertEquals(List.of("GET", "POST"), cors.getAllowedMethods());
            assertEquals(List.of("Authorization", "X-Fixture"), cors.getAllowedHeaders());
            assertEquals(Boolean.FALSE, cors.getAllowCredentials());
        });
    }

    @Test
    void protectedRequestWithoutCredentialsGets401WithoutRedirect() {
        configured().run(context -> {
            assertNull(context.getStartupFailure());
            MockMvc mvc = MockMvcBuilders.webAppContextSetup(context.getSourceApplicationContext())
                    .addFilters(context.getBean("springSecurityFilterChain", Filter.class)).build();
            mvc.perform(get("/fixture/private")).andExpect(status().isUnauthorized())
                    .andExpect(header().doesNotExist("Location"))
                    .andExpect(content().contentTypeCompatibleWith("application/json"));
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void preflightUsesExplicitAllowedOriginAndRejectsUnconfiguredOrigin(boolean foreign) {
        configured().withPropertyValues("security.cors.allowed-origins=https://fixture.example", "security.cors.allowed-methods=GET",
                "security.cors.allowed-headers=Authorization", "security.cors.allow-credentials=true").run(context -> {
            assertNull(context.getStartupFailure());
            MockMvc mvc = MockMvcBuilders.webAppContextSetup(context.getSourceApplicationContext())
                    .addFilters(context.getBean("springSecurityFilterChain", Filter.class)).build();
            var response = mvc.perform(options("/fixture/private").header("Origin", foreign ? "https://foreign.example" : "https://fixture.example")
                    .header("Access-Control-Request-Method", "GET").header("Access-Control-Request-Headers", "Authorization"));
            if (foreign) response.andExpect(status().isForbidden()).andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
            else response.andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", "https://fixture.example"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        });
    }

    private static Claims claims(String token) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(KEY)).build().parseClaimsJws(token).getBody();
    }

    private static int position(List<Filter> filters, Class<? extends Filter> type) {
        for (int i = 0; i < filters.size(); i++) if (type.isInstance(filters.get(i))) return i;
        throw new AssertionError("Expected filter absent: " + type.getSimpleName());
    }

    private static boolean hasCause(Throwable failure, Class<? extends Throwable> type) {
        for (Throwable cursor = failure; cursor != null; cursor = cursor.getCause()) if (type.isInstance(cursor)) return true;
        return false;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    @EnableWebMvc
    @Import({SecurityConfig.class, JwtService.class, JwtAuthenticationFilter.class, RestAuthenticationEntryPoint.class,
            RestAccessDeniedHandler.class, RateLimitConfig.class, AuthServiceImpl.class, RefreshTokenServiceImpl.class,
            RefreshTokenRevocationServiceImpl.class, InMemoryRateLimiterService.class, RateLimitKeyFactory.class})
    static class Fixture {
        @Bean ObjectMapper objectMapper() { return new ObjectMapper().registerModule(new JavaTimeModule()); }
        @Bean RefreshSessionStore refreshSessionStore() { return new InMemoryRefreshSessionStore(); }
        @Bean SecurityAuditService securityAuditService() { return (event, context) -> { }; }
    }
}
