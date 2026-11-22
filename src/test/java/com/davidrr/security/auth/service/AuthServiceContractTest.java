package com.davidrr.security.auth.service;

import com.davidrr.security.audit.*;
import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.event.UserRegisteredEvent;
import com.davidrr.security.auth.exception.*;
import com.davidrr.security.auth.port.*;
import com.davidrr.security.auth.service.impl.AuthServiceImpl;
import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.service.RefreshTokenService;
import com.davidrr.security.jwt.JwtService;
import com.davidrr.security.ratelimit.exception.RateLimitExceededException;
import com.davidrr.security.ratelimit.service.RateLimiterService;
import com.davidrr.security.ratelimit.util.RateLimitKeyFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** AUTH-01/02: direct collaboration tests; no transaction/commit guarantees. */
class AuthServiceContractTest {
    private final AuthenticationManager manager = mock(AuthenticationManager.class);
    private final JwtService jwt = mock(JwtService.class);
    private final RefreshTokenService refresh = mock(RefreshTokenService.class);
    private final UserProvider users = mock(UserProvider.class);
    private final RateLimiterService limiter = mock(RateLimiterService.class);
    private final SecurityAuditService audit = mock(SecurityAuditService.class);
    private final UserRegistrationPort registration = mock(UserRegistrationPort.class);
    private final ApplicationEventPublisher events = mock(ApplicationEventPublisher.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final UserLoginAuditPort loginAudit = mock(UserLoginAuditPort.class);
    private final SessionFingerprint fingerprint = new SessionFingerprint("192.0.2.20", "synthetic-agent");
    private final UserDetails principal = User.withUsername("canonical-user").password("encoded").authorities("FIXTURE").build();
    private final AuthRequest request = new AuthRequest("input-user", "synthetic-password");
    private AuthService service;

    @BeforeEach
    void setUp() {
        service = new AuthServiceImpl(manager, jwt, refresh, users, limiter, new RateLimitKeyFactory(), audit,
                registration, events, encoder, loginAudit);
    }

    @Test
    void loginIssuesTokensForAuthenticatedPrincipalAndRecordsSuccess() {
        when(manager.authenticate(any())).thenReturn(UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities()));
        when(jwt.generateToken(principal)).thenReturn("synthetic-access");
        when(refresh.createRefreshToken(principal.getUsername(), fingerprint)).thenReturn("synthetic-refresh");
        assertEquals(new AuthTokens("synthetic-access", "synthetic-refresh"), service.login(request, fingerprint));
        ArgumentCaptor<Authentication> authentication = ArgumentCaptor.forClass(Authentication.class);
        verify(manager).authenticate(authentication.capture());
        assertEquals("input-user", authentication.getValue().getName());
        assertEquals("synthetic-password", authentication.getValue().getCredentials());
        verify(refresh).cleanupExpired();
        verify(limiter).check("login", fingerprint.ip());
        verify(limiter).onSuccess("login", fingerprint.ip());
        verify(loginAudit).recordSuccessfulLogin("canonical-user");
        verify(audit).log(eq(SecurityEventType.LOGIN_SUCCESS), argThat(c -> "canonical-user".equals(c.username())));
        verify(limiter, never()).onFailure(anyString(), anyString());
    }

    static Stream<AuthenticationException> rejectedCredentials() {
        return Stream.of(new BadCredentialsException("synthetic"), new DisabledException("synthetic"));
    }

    @ParameterizedTest
    @MethodSource("rejectedCredentials")
    void rejectedAuthenticationDoesNotIssueTokens(AuthenticationException failure) {
        when(manager.authenticate(any())).thenThrow(failure);
        assertSame(failure, assertThrows(AuthenticationException.class, () -> service.login(request, fingerprint)));
        verify(limiter).onFailure("login", fingerprint.ip());
        verify(audit).log(eq(SecurityEventType.LOGIN_FAILURE), any());
        verifyNoInteractions(jwt, refresh, loginAudit);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rateLimitDenialCutsOffLoginOrRotationBeforeEmission(boolean refreshing) {
        String bucket = refreshing ? "refresh" : "login";
        doThrow(new RateLimitExceededException()).when(limiter).check(bucket, fingerprint.ip());
        assertThrows(RateLimitExceededException.class, () -> {
            if (refreshing) service.refresh("synthetic-refresh", fingerprint);
            else service.login(request, fingerprint);
        });
        verifyNoInteractions(manager, jwt, refresh, users, loginAudit);
        verify(audit).log(eq(SecurityEventType.RATE_LIMIT_EXCEEDED), any());
    }

    @Test
    void cleanupFailurePropagatesWithoutIssuingCredentials() {
        when(manager.authenticate(any())).thenReturn(UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities()));
        RuntimeException unavailable = new IllegalStateException("synthetic-dependency-failure");
        doThrow(unavailable).when(refresh).cleanupExpired();
        assertSame(unavailable, assertThrows(RuntimeException.class, () -> service.login(request, fingerprint)));
        verifyNoInteractions(jwt, loginAudit);
        verify(refresh, never()).createRefreshToken(anyString(), any());
    }

    @Test
    void loginAuditFailureDoesNotReturnSuccessfulResult() {
        when(manager.authenticate(any())).thenReturn(UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities()));
        when(jwt.generateToken(principal)).thenReturn("synthetic-access");
        when(refresh.createRefreshToken(principal.getUsername(), fingerprint)).thenReturn("synthetic-refresh");
        doThrow(new IllegalStateException("synthetic-audit-failure")).when(loginAudit).recordSuccessfulLogin("canonical-user");
        assertThrows(IllegalStateException.class, () -> service.login(request, fingerprint));
        // Direct invocation does not establish rollback of earlier token creation.
    }

    @Test
    void registrationEncodesPasswordPublishesGenericEventAndUsesReturnedIdentity() {
        RegisterRequest input = new RegisterRequest();
        input.setUsername("input-user"); input.setEmail("fixture@example.invalid"); input.setPassword("synthetic-password");
        when(encoder.encode("synthetic-password")).thenReturn("synthetic-encoded");
        when(registration.register("input-user", "fixture@example.invalid", "synthetic-encoded"))
                .thenReturn(new UserRegistrationPort.RegisteredUser(7L, "canonical-user"));
        when(users.loadUserByUsername("canonical-user")).thenReturn(principal);
        when(jwt.generateToken(principal)).thenReturn("synthetic-access");
        when(refresh.createRefreshToken("canonical-user", fingerprint)).thenReturn("synthetic-refresh");
        assertEquals(new AuthTokens("synthetic-access", "synthetic-refresh"), service.register(input, fingerprint));
        verify(registration).register("input-user", "fixture@example.invalid", "synthetic-encoded");
        verify(events).publishEvent(new UserRegisteredEvent(7L, "canonical-user"));
        verify(audit).log(eq(SecurityEventType.REGISTER_SUCCESS), any());
    }

    @Test
    void failedRegistrationDoesNotPublishOrIssueTokens() {
        when(registration.register(any(), any(), any())).thenThrow(new IllegalStateException("synthetic-registration-failure"));
        assertThrows(IllegalStateException.class, () -> service.register(new RegisterRequest(), fingerprint));
        verifyNoInteractions(events, jwt, refresh, users);
    }

    @Test
    void refreshReturnsRotatedSuccessorAndJwtForRotationIdentity() {
        when(refresh.rotate("synthetic-old", fingerprint)).thenReturn(new RefreshRotationResult("canonical-user", "synthetic-next"));
        when(users.loadUserByUsername("canonical-user")).thenReturn(principal);
        when(jwt.generateToken(principal)).thenReturn("synthetic-access");
        assertEquals(new AuthTokens("synthetic-access", "synthetic-next"), service.refresh("synthetic-old", fingerprint));
        verify(limiter).onSuccess("refresh", fingerprint.ip());
        verify(audit).log(eq(SecurityEventType.REFRESH_SUCCESS), any());
    }

    static Stream<RuntimeException> rotationFailures() {
        return Stream.of(new RefreshTokenInvalidException(), new RefreshTokenExpiredException(), new RefreshTokenReuseException(),
                new SuspiciousSessionException(), new IllegalStateException("synthetic-store-failure"));
    }

    @ParameterizedTest
    @MethodSource("rotationFailures")
    void failedRotationDoesNotLoadIdentityOrIssueAccessToken(RuntimeException failure) {
        when(refresh.rotate("synthetic-old", fingerprint)).thenThrow(failure);
        assertSame(failure, assertThrows(RuntimeException.class, () -> service.refresh("synthetic-old", fingerprint)));
        verifyNoInteractions(users, jwt);
        verify(limiter).onFailure("refresh", fingerprint.ip());
        verify(limiter, never()).onSuccess(anyString(), anyString());
    }

    @Test
    void refreshIdentityDependencyFailureDoesNotIssueAccessToken() {
        when(refresh.rotate("synthetic-old", fingerprint)).thenReturn(new RefreshRotationResult("canonical-user", "synthetic-next"));
        when(users.loadUserByUsername("canonical-user")).thenThrow(new IllegalStateException("synthetic-identity-failure"));
        assertThrows(IllegalStateException.class, () -> service.refresh("synthetic-old", fingerprint));
        verifyNoInteractions(jwt);
        verify(limiter).onFailure("refresh", fingerprint.ip());
    }

    @Test
    void logoutDelegatesRevocation() {
        service.logout("synthetic-current");
        verify(refresh).revoke("synthetic-current");
        verifyNoInteractions(jwt, users);
    }

    @Test
    void logoutAllResolvesCurrentSessionAndDelegatesAccountRevocation() {
        when(refresh.findSessionByToken("synthetic-current")).thenReturn(RefreshSession.builder().username("alpha").build());
        service.logoutAll("synthetic-current");
        verify(refresh).revokeAll("alpha");
        // This valid-session delegation does not endorse revoked tokens as authorization.
    }

    @Test
    void sessionListingReturnsCollaboratorResult() {
        List<SessionResponse> expected = List.of(new SessionResponse(7L, null, null, null, null, null, null, true));
        when(refresh.getActiveSessions("synthetic-current")).thenReturn(expected);
        assertSame(expected, service.getSessions("synthetic-current"));
    }

    @Test
    void targetedRevocationPassesTokenAndSessionId() {
        service.revokeSession("synthetic-current", 7L);
        verify(refresh).revokeSession("synthetic-current", 7L);
    }
}
