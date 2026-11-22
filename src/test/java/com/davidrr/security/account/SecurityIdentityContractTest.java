package com.davidrr.security.account;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import java.time.Duration;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SecurityIdentityContractTest {
    @Test void opaqueIdentifiersAndNamespacesAreExact() {
        String uuid = UUID.fromString("a4d63919-4754-4b57-b668-3017a00dd1ae").toString();
        for (String subject : List.of("external:alpha", uuid, "7", "007", "\uD83D\uDE00".repeat(256))) {
            assertEquals(subject, new SecurityIdentity("fixture", subject).subjectId());
        }
        assertNotEquals(new SecurityIdentity("fixture", "7"), new SecurityIdentity("fixture", "007"));
        assertNotEquals(new SecurityIdentity("one", "alpha"), new SecurityIdentity("two", "alpha"));
        assertNotEquals(new SecurityIdentity("one", "Alpha"), new SecurityIdentity("one", "alpha"));
    }
    @ParameterizedTest @NullAndEmptySource @ValueSource(strings = {" ", " alpha", "alpha ", "x\n", "\uD800", "\uDC00", "\u00A0x"})
    void rejectsInvalidSubjects(String subject) { assertThrows(IllegalArgumentException.class, () -> new SecurityIdentity("fixture", subject)); }
    @ParameterizedTest @NullAndEmptySource @ValueSource(strings = {"x y", "x/", "\u00F1", "*", "fixture\n"})
    void rejectsInvalidNamespaces(String namespace) { assertThrows(IllegalArgumentException.class, () -> new SecurityIdentity(namespace, "alpha")); }
    @Test void boundariesAndDefensiveCopies() {
        assertDoesNotThrow(() -> new SecurityIdentity("a".repeat(128), "x".repeat(256)));
        assertThrows(IllegalArgumentException.class, () -> new SecurityIdentity("a".repeat(129), "x"));
        assertThrows(IllegalArgumentException.class, () -> new SecurityIdentity("a", "x".repeat(257)));
        Set<String> namespaces = new HashSet<>(Set.of("fixture"));
        AccountSecurityPolicy policy = new AccountSecurityPolicy("ctx", namespaces, Duration.ofSeconds(1));
        namespaces.clear(); assertEquals(Set.of("fixture"), policy.acceptedNamespaces());
        Set<String> authorities = new HashSet<>(Set.of("scope:read"));
        AccountSecuritySnapshot snapshot = new AccountSecuritySnapshot(new SecurityIdentity("fixture", "id"), AdmissionState.ADMITTED,
                new SecurityRevision("generation-v1", "opaque"), "name", authorities);
        authorities.clear(); assertEquals(Set.of("scope:read"), snapshot.authorities());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.authorities().add("scope:write"));
        assertTrue(snapshot.toString().contains("REDACTED")); assertFalse(snapshot.toString().contains("name"));
    }
    @Test void invalidPoliciesAndSnapshotsNeverBecomeAdmissionDefaults() {
        for (Duration budget : List.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(Long.MAX_VALUE))) {
            assertThrows(IllegalArgumentException.class, () -> new AccountSecurityPolicy("ctx", Set.of("fixture"), budget));
        }
        assertThrows(IllegalArgumentException.class, () -> new AccountSecurityPolicy("ctx", Set.of(), Duration.ofSeconds(1)));
        assertThrows(NullPointerException.class, () -> new AccountSecuritySnapshot(new SecurityIdentity("fixture", "id"), null,
                new SecurityRevision("counter-v1", "0"), "name", Set.of()));
        assertThrows(NullPointerException.class, () -> new TokenAccountClaims(null, new SecurityRevision("counter-v1", "0")));
        assertThrows(IllegalArgumentException.class, () -> new SecurityRevision("bad scheme", "0"));
        assertThrows(IllegalArgumentException.class, () -> new SecurityRevision("counter-v1", ""));
    }
    @Test void representationsAndExceptionsDoNotRetainPayloads() {
        for (Object value : List.of(new SecurityIdentity("fixture", "sensitive-id"), new SecurityRevision("counter-v1", "123"),
                new TokenAccountClaims(new SecurityIdentity("fixture", "sensitive-id"), new SecurityRevision("counter-v1", "123")))) {
            assertTrue(value.toString().contains("REDACTED")); assertFalse(value.toString().contains("sensitive-id"));
        }
        SecurityValidationException error = new SecurityValidationException(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE);
        assertEquals(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE, error.failure()); assertNull(error.getCause());
        assertThrows(IllegalStateException.class, () -> error.initCause(new RuntimeException("external-secret")));
    }
}
