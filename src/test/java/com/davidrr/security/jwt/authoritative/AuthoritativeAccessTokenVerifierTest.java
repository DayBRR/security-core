package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import java.lang.reflect.Modifier;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static com.davidrr.security.jwt.authoritative.JwtCryptographicVerifierTest.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthoritativeAccessTokenVerifierTest {
    static AccountSecuritySnapshot snapshot(SecurityIdentity id, String name, AdmissionState state, String revision) {
        return new AccountSecuritySnapshot(id,state,new SecurityRevision("counter-v1",revision),name,Set.of("scope:current"));
    }
    static AccountSecurityPolicy accountPolicy(String context) { return new AccountSecurityPolicy(context,Set.of("fixture"),Duration.ofSeconds(5)); }
    static AuthoritativeAccessTokenVerifier composed(AccountSecurityPort port, Clock clock) {
        return new AuthoritativeAccessTokenVerifier(verifier(clock),new StrictIdentityClaimsCodec("ctx",Set.of("counter-v1")),
                new AccountSecurityGate(port,accountPolicy("ctx")),clock);
    }
    @Test void validTokenUsesExactlyOneCurrentSnapshotAndNoStoredCredentials() {
        AtomicInteger calls = new AtomicInteger();
        VerifiedAccessIdentity result = composed((id,t) -> { calls.incrementAndGet(); return Optional.of(snapshot(id,"renamed-user",AdmissionState.ADMITTED,"7")); },CLOCK)
                .verify(sign(HEADER,BODY));
        assertEquals(1,calls.get()); assertEquals("opaque:alpha",result.snapshot().identity().subjectId());
        assertEquals("renamed-user",result.snapshot().principalName()); assertEquals(Set.of("scope:current"),result.snapshot().authorities());
        assertEquals("ctx",result.securityContextId()); assertEquals(Instant.ofEpochSecond(1900000900),result.tokenExpiresAt());
        assertEquals("VerifiedAccessIdentity[REDACTED]",result.toString());
        assertThrows(UnsupportedOperationException.class, () -> result.snapshot().authorities().add("root"));
    }
    @ParameterizedTest @MethodSource("com.davidrr.security.jwt.authoritative.JwtCryptographicVerifierTest#badHeaders")
    void adversarialHeaderNeverReachesAccount(String header) { noRead(sign(header,BODY)); }
    @ParameterizedTest @MethodSource("com.davidrr.security.jwt.authoritative.JwtCryptographicVerifierTest#badPayloads")
    void adversarialPayloadNeverReachesAccount(String body) { noRead(sign(HEADER,body)); }
    @ParameterizedTest @ValueSource(strings = {"\"security_revision\":7", "\"security_revision\":\"01\"", "\"security_revision\":\"9223372036854775808\""})
    void invalidRevisionNeverReachesAccount(String replacement) { noRead(sign(HEADER,BODY.replace("\"security_revision\":\"7\"",replacement))); }
    private void noRead(String token) {
        AtomicInteger calls = new AtomicInteger();
        assertThrows(SecurityValidationException.class, () -> composed((id,t) -> { calls.incrementAndGet(); return Optional.empty(); },CLOCK).verify(token));
        assertEquals(0,calls.get());
    }
    @Test void accountAbsenceDependencyAndAdmissionNeverFallback() {
        String token = sign(HEADER,BODY);
        assertFailure(SecurityValidationFailure.IDENTITY_ABSENT, () -> composed((id,t)->Optional.empty(),CLOCK).verify(token));
        assertFailure(SecurityValidationFailure.ACCOUNT_NOT_ADMITTED, () -> composed((id,t)->Optional.of(snapshot(id,"pending",AdmissionState.NOT_ADMITTED,"7")),CLOCK).verify(token));
        assertFailure(SecurityValidationFailure.REVISION_MISMATCH, () -> composed((id,t)->Optional.of(snapshot(id,"same-name",AdmissionState.ADMITTED,"8")),CLOCK).verify(token));
        assertFailure(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE, () -> composed((id,t)->{throw new SecurityValidationException(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE);},CLOCK).verify(token));
        assertFailure(SecurityValidationFailure.CONTRACT_VIOLATION, () -> composed((id,t)->Optional.of(snapshot(new SecurityIdentity("fixture","recreated-id"),"same-name",AdmissionState.ADMITTED,"7")),CLOCK).verify(token));
        noRead(sign(HEADER,BODY.replace("\"fixture\"","\"foreign\"")));
    }
    @Test void expiresDuringReadAndNoResultCrossesContexts() {
        AtomicReference<Instant> now = new AtomicReference<>(NOW);
        Clock clock = new Clock() {
            public ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(ZoneId zone) { return this; }
            public Instant instant() { return now.get(); }
        };
        assertFailure(SecurityValidationFailure.TOKEN_INVALID, () -> composed((id,t) -> {
            now.set(Instant.ofEpochSecond(1900000900)); return Optional.of(snapshot(id,"name",AdmissionState.ADMITTED,"7"));
        },clock).verify(sign(HEADER,BODY)));
        assertThrows(IllegalArgumentException.class, () -> new AuthoritativeAccessTokenVerifier(verifier(CLOCK),
                new StrictIdentityClaimsCodec("other",Set.of("counter-v1")),new AccountSecurityGate((id,t)->Optional.empty(),accountPolicy("ctx")),CLOCK));
        assertThrows(IllegalArgumentException.class, () -> new AuthoritativeAccessTokenVerifier(verifier(CLOCK),
                new StrictIdentityClaimsCodec("ctx",Set.of("counter-v1")),new AccountSecurityGate((id,t)->Optional.empty(),accountPolicy("other")),CLOCK));
    }
    @Test void cannotConstructVerifiedResultsOrAutoActivateThroughScanning() {
        for (Class<?> type : List.of(VerifiedAccessIdentity.class,VerifiedJwtClaims.class)) {
            assertEquals(0,type.getConstructors().length); assertTrue(Modifier.isFinal(type.getModifiers()));
        }
        for (Class<?> type : List.of(JwtCryptographicVerifier.class,StrictIdentityClaimsCodec.class,AuthoritativeAccessTokenVerifier.class,AccountSecurityGate.class)) {
            assertEquals(0,type.getDeclaredAnnotations().length);
        }
        var scanner = new org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider(true);
        assertTrue(scanner.findCandidateComponents("com.davidrr.security.account").isEmpty());
        assertTrue(scanner.findCandidateComponents("com.davidrr.security.jwt.authoritative").isEmpty());
    }
    @Test void concurrentVerificationHasNoSharedPerRequestState() throws Exception {
        AuthoritativeAccessTokenVerifier verifier = composed((id,t)->Optional.of(snapshot(id,id.subjectId(),AdmissionState.ADMITTED,"7")),CLOCK);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<String>> operations = new ArrayList<>();
            for (int i=0;i<32;i++) {
                String subject = "opaque:" + i;
                String token = sign(HEADER,BODY.replace("opaque:alpha",subject));
                operations.add(()->verifier.verify(token).snapshot().identity().subjectId());
            }
            List<Future<String>> results = executor.invokeAll(operations,10,TimeUnit.SECONDS);
            for (int i=0;i<32;i++) assertEquals("opaque:"+i,results.get(i).get());
        } finally { executor.shutdownNow(); }
    }
    private static void assertFailure(SecurityValidationFailure failure, Runnable operation) {
        assertEquals(failure,assertThrows(SecurityValidationException.class,operation::run).failure());
    }
}
