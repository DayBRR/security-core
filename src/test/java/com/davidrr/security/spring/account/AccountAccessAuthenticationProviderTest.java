package com.davidrr.security.spring.account;

import com.davidrr.security.account.*;
import com.davidrr.security.jwt.authoritative.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.*;
import javax.crypto.spec.SecretKeySpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class AccountAccessAuthenticationProviderTest {
    /** Shared synthetic fixture, nested here to keep the authorized file inventory closed. */
    static final class Fixture {
        static final Instant NOW = Instant.ofEpochSecond(1900000100);
        static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        final AtomicReference<Instant> now = new AtomicReference<>(NOW);
        final Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        final AtomicInteger reads = new AtomicInteger();
        final AtomicInteger effects = new AtomicInteger();
        final AtomicReference<RuntimeException> failure = new AtomicReference<>();
        final SecurityIdentity identity = new SecurityIdentity("fixture", "external:alpha");
        final AtomicReference<AccountSecuritySnapshot> state = new AtomicReference<>(snapshot(identity, "7", AdmissionState.ADMITTED));
        AccessPrincipalMapper mapper = snapshot -> new MappedAccessPrincipal(snapshot.identity(), user(snapshot));

        static AccountSecuritySnapshot snapshot(SecurityIdentity id, String revision, AdmissionState admission) {
            return new AccountSecuritySnapshot(id, admission, new SecurityRevision("counter-v1", revision), "current-name", Set.of("scope:read"));
        }
        static UserDetails user(AccountSecuritySnapshot s) {
            return User.withUsername(s.principalName()).password("").authorities(s.authorities().toArray(String[]::new)).build();
        }
        AuthoritativeAccessTokenVerifier verifier() {
            JwtVerificationPolicy policy = new JwtVerificationPolicy("ctx", "fixture-issuer", Set.of("fixture-resource"), Set.of("HS256"),
                    Duration.ZERO, Duration.ofMinutes(15), new JwtReadLimits(8192,1024,4096,8,256,64,1024,20));
            return new AuthoritativeAccessTokenVerifier(new JwtCryptographicVerifier(policy,
                    (kid,alg) -> new SecretKeySpec(KEY,"HmacSHA256"),clock),new StrictIdentityClaimsCodec("ctx",Set.of("counter-v1")),
                    new AccountSecurityGate((id,timeout) -> {
                        reads.incrementAndGet();
                        if (failure.get() != null) throw failure.get();
                        return Optional.ofNullable(state.get());
                    },new AccountSecurityPolicy("ctx",Set.of("fixture"),Duration.ofSeconds(5))),clock);
        }
        AccountAccessAuthenticationProvider provider() { return new AccountAccessAuthenticationProvider(verifier(), s -> mapper.map(s), clock); }
        AccountAuthenticationFailureHandler writer() {
            return new AccountAuthenticationFailureHandler(new com.fasterxml.jackson.databind.ObjectMapper()
                    .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule()),clock);
        }
        AuthoritativeBearerFilter filter() { return new AuthoritativeBearerFilter(provider(),writer(), r -> true); }
        String token() { return token(identity.subjectId(),"7",1900000900L,KEY); }
        String token(String subject, String revision, long expires, byte[] key) {
            return Jwts.builder().setHeaderParam("typ","at+jwt").setIssuer("fixture-issuer").setAudience("fixture-resource")
                    .setSubject(subject).setId("fixture-id").setIssuedAt(Date.from(Instant.ofEpochSecond(1900000000)))
                    .setExpiration(Date.from(Instant.ofEpochSecond(expires))).claim("identity_namespace","fixture")
                    .claim("security_revision_scheme","counter-v1").claim("security_revision",revision).claim("token_use","access")
                    .signWith(new SecretKeySpec(key,"HmacSHA256"),SignatureAlgorithm.HS256).compact();
        }
    }

    @Test void validJwtMapsExactlyOneAuthoritativeReadAndErasesInput() {
        Fixture f = new Fixture();
        var input = new AccountAccessAuthenticationToken(f.token());
        var result = f.provider().authenticate(input);
        assertTrue(result.isAuthenticated()); assertNull(result.getCredentials()); assertNull(input.compactToken());
        assertEquals("current-name",result.getName()); assertEquals(1,f.reads.get());
        assertEquals(Set.of("scope:read"),result.getAuthorities().stream().map(a -> a.getAuthority()).collect(java.util.stream.Collectors.toSet()));
        assertThrows(UnsupportedOperationException.class, () -> result.getAuthorities().clear());
    }
    @ParameterizedTest @ValueSource(strings={"absent","disabled","revision","contract","dependency"})
    void authoritativeRejectionsNeverReturnAnAuthentication(String scenario) {
        Fixture f = new Fixture();
        switch(scenario) {
            case "absent" -> f.state.set(null);
            case "disabled" -> f.state.set(Fixture.snapshot(f.identity,"7",AdmissionState.NOT_ADMITTED));
            case "revision" -> f.state.set(Fixture.snapshot(f.identity,"8",AdmissionState.ADMITTED));
            case "contract" -> f.state.set(Fixture.snapshot(new SecurityIdentity("fixture","other"),"7",AdmissionState.ADMITTED));
            default -> f.failure.set(new SecurityValidationException(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE));
        }
        var input = new AccountAccessAuthenticationToken(f.token());
        Class<? extends Exception> expected = Set.of("contract","dependency").contains(scenario)
                ? AuthoritativeAuthenticationServiceException.class : BadCredentialsException.class;
        assertThrows(expected, () -> f.provider().authenticate(input));
        assertNull(input.compactToken()); assertEquals(1,f.reads.get());
    }
    @ParameterizedTest @ValueSource(strings={"id","name","extra","missing","password","enabled","locked","expired","credentials","null"})
    void incoherentMappingsAreKnownServiceFailures(String scenario) {
        Fixture f = new Fixture();
        f.mapper = s -> {
            if(scenario.equals("null")) return null;
            var builder = User.withUsername(scenario.equals("name")?"wrong":s.principalName()).password(scenario.equals("password")?"hash":"")
                    .authorities(scenario.equals("extra")?new String[]{"scope:read","root"}:scenario.equals("missing")?new String[]{}:new String[]{"scope:read"})
                    .disabled(scenario.equals("enabled")).accountLocked(scenario.equals("locked"))
                    .accountExpired(scenario.equals("expired")).credentialsExpired(scenario.equals("credentials"));
            return new MappedAccessPrincipal(scenario.equals("id")?new SecurityIdentity("fixture","wrong"):s.identity(),builder.build());
        };
        assertThrows(AuthoritativeAuthenticationServiceException.class, () -> f.provider().authenticate(new AccountAccessAuthenticationToken(f.token())));
    }
    @Test void expiryAfterMapperIsCheckedAndUnexpectedBugsAreNotReclassified() {
        Fixture f = new Fixture();
        f.mapper = s -> { f.now.set(Instant.ofEpochSecond(1900000900)); return new MappedAccessPrincipal(s.identity(),Fixture.user(s)); };
        assertThrows(BadCredentialsException.class, () -> f.provider().authenticate(new AccountAccessAuthenticationToken(f.token())));
        f.now.set(Fixture.NOW);
        var bug = new IllegalStateException("external-sensitive-sentinel"); f.mapper = s -> { throw bug; };
        var input = new AccountAccessAuthenticationToken(f.token());
        assertSame(bug,assertThrows(IllegalStateException.class, () -> f.provider().authenticate(input)));
        assertNull(input.compactToken());
    }
    @Test void cryptoFailsBeforeLookupAndOnlyDedicatedInputIsSupported() {
        Fixture f = new Fixture(); var p=f.provider();
        assertTrue(p.supports(AccountAccessAuthenticationToken.class)); assertFalse(p.supports(UsernamePasswordAuthenticationToken.class));
        assertNull(p.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("name","password")));
        for(String token:List.of("legacy",f.token("external:alpha","7",1900000100L,Fixture.KEY),
                f.token("external:alpha","7",1900000900L,new byte[32]))) {
            assertThrows(BadCredentialsException.class, () -> p.authenticate(new AccountAccessAuthenticationToken(token)));
        }
        assertEquals(0,f.reads.get());
        var result=p.authenticate(new AccountAccessAuthenticationToken(f.token()));
        assertThrows(BadCredentialsException.class, () -> p.authenticate(result));
    }
    @Test void emptyAuthoritiesAndUuidConsumersNeedNoProductRole() {
        Fixture f=new Fixture(); var id=new SecurityIdentity("fixture","a4d63919-4754-4b57-b668-3017a00dd1ae");
        f.state.set(new AccountSecuritySnapshot(id,AdmissionState.ADMITTED,new SecurityRevision("counter-v1","7"),"uuid-name",Set.of()));
        var result=f.provider().authenticate(new AccountAccessAuthenticationToken(f.token(id.subjectId(),"7",1900000900,Fixture.KEY)));
        assertEquals("uuid-name",result.getName()); assertTrue(result.getAuthorities().isEmpty());
    }
    @Test void mutableGrantedAuthoritiesCannotAlterPublishedPermissionsAndMalformedCollectionsFail() {
        Fixture f=new Fixture();var value=new AtomicReference<>("scope:read");
        UserDetails principal=new UserDetails(){
            public String getUsername(){return "current-name";} public String getPassword(){return null;}
            public Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities(){return List.of(()->value.get());}
        };
        f.mapper=s->new MappedAccessPrincipal(s.identity(),principal);
        var result=f.provider().authenticate(new AccountAccessAuthenticationToken(f.token()));
        value.set("root");assertEquals("scope:read",result.getAuthorities().iterator().next().getAuthority());
        for(int scenario=0;scenario<4;scenario++){
            int selected=scenario;
            var bad=org.mockito.Mockito.mock(UserDetails.class);
            org.mockito.Mockito.when(bad.getUsername()).thenReturn("current-name");
            org.mockito.Mockito.when(bad.isEnabled()).thenReturn(true);org.mockito.Mockito.when(bad.isAccountNonLocked()).thenReturn(true);
            org.mockito.Mockito.when(bad.isAccountNonExpired()).thenReturn(true);org.mockito.Mockito.when(bad.isCredentialsNonExpired()).thenReturn(true);
            Collection<org.springframework.security.core.GrantedAuthority> authorities=switch(selected){
                case 0->null;case 1->Arrays.asList((org.springframework.security.core.GrantedAuthority)null);
                case 2->List.of(()->null);default->List.of(()->"scope:read",()->"scope:read");};
            org.mockito.Mockito.doReturn(authorities).when(bad).getAuthorities();f.mapper=s->new MappedAccessPrincipal(s.identity(),bad);
            assertThrows(AuthoritativeAuthenticationServiceException.class,()->f.provider().authenticate(new AccountAccessAuthenticationToken(f.token())));
        }
    }
}
