package com.davidrr.security.jwt;

import com.davidrr.security.auth.port.UserProvider;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterContractTest {
    private final JwtService jwt = mock(JwtService.class);
    private final UserProvider users = mock(UserProvider.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwt, users);
    private final UserDetails user = User.withUsername("alpha").password("encoded").authorities("FIXTURE_READ").build();

    @BeforeEach
    void startWithEmptyContext() { SecurityContextHolder.clearContext(); }

    @AfterEach
    void clearContext() { SecurityContextHolder.clearContext(); }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Basic synthetic", "unrelated"})
    void requestsWithoutBearerContinueWithoutAuthenticating(String header) throws Exception {
        invoke(header);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(jwt, users);
    }

    @Test
    void validBearerInstallsPrincipalAndItsAuthoritiesForTheChain() throws Exception {
        when(jwt.extractUsername("synthetic-token")).thenReturn("alpha");
        when(users.loadUserByUsername("alpha")).thenReturn(user);
        when(jwt.isTokenValid("synthetic-token", user)).thenReturn(true);
        MockHttpServletRequest request = request("Bearer synthetic-token");
        FilterChain chain = mock(FilterChain.class);
        doAnswer(invocation -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(authentication);
            assertTrue(authentication.isAuthenticated());
            assertSame(user, authentication.getPrincipal());
            assertEquals(new java.util.HashSet<>(user.getAuthorities()), new java.util.HashSet<>(authentication.getAuthorities()));
            assertNull(authentication.getCredentials());
            return null;
        }).when(chain).doFilter(eq(request), any());
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        verify(chain).doFilter(eq(request), any());
    }

    @Test
    void existingAuthenticationIsNotReplacedByAnotherValidBearer() throws Exception {
        Authentication existing = UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(existing);
        when(jwt.extractUsername("synthetic-token")).thenReturn("beta");
        invoke("Bearer synthetic-token");
        assertSame(existing, SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(users);
        verify(jwt, never()).isTokenValid(anyString(), any());
    }

    @Test
    void validationFalseContinuesWithoutAuthentication() throws Exception {
        when(jwt.extractUsername("synthetic-token")).thenReturn("alpha");
        when(users.loadUserByUsername("alpha")).thenReturn(user);
        when(jwt.isTokenValid("synthetic-token", user)).thenReturn(false);
        invoke("Bearer synthetic-token");
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void jwtOrArgumentFailureDoesNotAuthenticateAndStillContinues(boolean illegalArgument) throws Exception {
        RuntimeException failure = illegalArgument ? new IllegalArgumentException("synthetic") : new MalformedJwtException("synthetic");
        when(jwt.extractUsername("synthetic-token")).thenThrow(failure);
        invoke("Bearer synthetic-token");
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verifyNoInteractions(users);
    }

    private void invoke(String header) throws Exception {
        MockHttpServletRequest request = request(header);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    private static MockHttpServletRequest request(String header) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/fixture/resource");
        if (header != null) request.addHeader("Authorization", header);
        return request;
    }
}
