package com.davidrr.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceContractTest {
    // Synthetic key only. The context applies real @Value and @PostConstruct wiring.
    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    private AnnotationConfigApplicationContext context;
    private JwtService service;
    private final UserDetails user = User.withUsername("alpha").password("encoded").authorities("FIXTURE_READ", "FIXTURE_WRITE").build();

    @BeforeEach
    void startContext() {
        context = new AnnotationConfigApplicationContext();
        TestPropertyValues.of("security.jwt.secret-key=" + Base64.getEncoder().encodeToString(KEY),
                "security.jwt.issuer=fixture-issuer", "security.jwt.expiration=600000").applyTo(context);
        context.register(JwtService.class);
        context.refresh();
        service = context.getBean(JwtService.class);
    }

    @AfterEach
    void closeContext() { context.close(); }

    @Test
    void bothGenerationOverloadsPreserveClaimsAndExtractors() {
        String fromUser = service.generateToken(user);
        String fromArguments = service.generateToken("alpha", List.of("FIXTURE_READ", "FIXTURE_WRITE"));
        for (String token : List.of(fromUser, fromArguments)) {
            Claims claims = Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(KEY)).build().parseClaimsJws(token).getBody();
            assertEquals("alpha", claims.getSubject());
            assertEquals("fixture-issuer", claims.getIssuer());
            assertNotNull(claims.getIssuedAt());
            assertTrue(claims.getExpiration().toInstant().isAfter(Instant.now().plusSeconds(590)));
            assertTrue(claims.getExpiration().toInstant().isBefore(Instant.now().plusSeconds(610)));
            assertDoesNotThrow(() -> UUID.fromString(claims.getId()));
            assertEquals("alpha", service.extractUsername(token));
            assertEquals(claims.getId(), service.extractJti(token));
            assertEquals(List.of("FIXTURE_READ", "FIXTURE_WRITE"), service.extractRoles(token));
            assertTrue(service.isTokenValid(token, user));
        }
        assertNotEquals(service.extractJti(fromUser), service.extractJti(fromArguments));
    }

    @Test
    void alteredSignatureCannotBeParsedOrValidated() {
        String token = service.generateToken(user);
        int start = token.lastIndexOf('.') + 1;
        String altered = token.substring(0, start) + (token.charAt(start) == 'A' ? 'B' : 'A') + token.substring(start + 1);
        assertThrows(JwtException.class, () -> service.extractUsername(altered));
        assertThrows(JwtException.class, () -> service.isTokenValid(altered, user));
    }

    @Test
    void tokenSignedWithAnotherKeyCannotBeValidated() {
        byte[] foreign = "abcdef0123456789abcdef0123456789".getBytes(StandardCharsets.US_ASCII);
        String token = Jwts.builder().setSubject("alpha").setExpiration(Date.from(Instant.now().plusSeconds(600)))
                .signWith(Keys.hmacShaKeyFor(foreign)).compact();
        assertThrows(JwtException.class, () -> service.isTokenValid(token, user));
    }

    @ParameterizedTest
    @ValueSource(strings = {"synthetic-malformed", "a.b.c"})
    void malformedTokensCannotBeValidated(String token) {
        assertThrows(JwtException.class, () -> service.isTokenValid(token, user));
    }

    @Test
    void expiredSignedTokenIsRejected() {
        String expired = signed("alpha", "fixture-issuer", Instant.now().minusSeconds(3600));
        assertThrows(ExpiredJwtException.class, () -> service.isTokenValid(expired, user));
    }

    @Test
    void issuerAndSubjectMismatchAreRejected() {
        assertFalse(service.isTokenValid(signed("alpha", "foreign-issuer", Instant.now().plusSeconds(600)), user));
        UserDetails other = User.withUsername("beta").password("encoded").authorities("FIXTURE_READ").build();
        assertFalse(service.isTokenValid(service.generateToken(user), other));
    }

    @Test
    void missingRolesClaimExtractsEmptyList() {
        assertEquals(List.of(), service.extractRoles(signed("alpha", "fixture-issuer", Instant.now().plusSeconds(600))));
    }

    private static String signed(String subject, String issuer, Instant expires) {
        return Jwts.builder().setSubject(subject).setIssuer(issuer).setIssuedAt(Date.from(Instant.now().minusSeconds(7200)))
                .setExpiration(Date.from(expires)).signWith(Keys.hmacShaKeyFor(KEY)).compact();
    }
}
