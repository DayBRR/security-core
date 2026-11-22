package com.davidrr.security.account;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.davidrr.security.account.SecurityValidationFailure.*;

class AccountSecurityGateTest {
    private final SecurityIdentity identity = new SecurityIdentity("fixture", "opaque:alpha");
    private final SecurityRevision revision = new SecurityRevision("counter-v1", "7");
    private final AccountSecurityPolicy policy = new AccountSecurityPolicy("ctx", Set.of("fixture"), Duration.ofNanos(100));
    private TokenAccountClaims claims() { return new TokenAccountClaims(identity, revision); }
    private AccountSecuritySnapshot snapshot(SecurityIdentity id, AdmissionState state, SecurityRevision rev) {
        return new AccountSecuritySnapshot(id, state, rev, "current-name", Set.of("scope:read"));
    }
    private static void failure(SecurityValidationFailure reason, Runnable call) {
        assertEquals(reason, assertThrows(SecurityValidationException.class, call::run).failure());
    }
    @Test void oneReadWithRemainingBudgetAndCurrentAuthorities() {
        AtomicLong nanos = new AtomicLong(10); AtomicInteger calls = new AtomicInteger();
        AccountSecuritySnapshot expected = snapshot(identity, AdmissionState.ADMITTED, revision);
        AccountSecurityGate gate = new AccountSecurityGate((id, timeout) -> {
            calls.incrementAndGet(); assertEquals(identity, id); assertEquals(Duration.ofNanos(90), timeout);
            return Optional.of(expected);
        }, policy, () -> nanos.getAndAdd(10));
        assertSame(expected, gate.requireForAccess(claims())); assertEquals(1, calls.get()); assertEquals("ctx", gate.securityContextId());
    }
    @Test void absentNotAdmittedMismatchAndImpossibleResponseAreDistinct() {
        failure(IDENTITY_ABSENT, () -> new AccountSecurityGate((id,t) -> Optional.empty(), policy, () -> 0).requireForAccess(claims()));
        failure(ACCOUNT_NOT_ADMITTED, () -> new AccountSecurityGate((id,t) -> Optional.of(snapshot(id, AdmissionState.NOT_ADMITTED, revision)), policy, () -> 0).requireForAccess(claims()));
        for (SecurityRevision other : List.of(new SecurityRevision("counter-v1", "6"), new SecurityRevision("counter-v1", "8"), new SecurityRevision("generation-v1", "7"))) {
            failure(REVISION_MISMATCH, () -> new AccountSecurityGate((id,t) -> Optional.of(snapshot(id, AdmissionState.ADMITTED, other)), policy, () -> 0).requireForAccess(claims()));
        }
        failure(CONTRACT_VIOLATION, () -> new AccountSecurityGate((id,t) -> null, policy, () -> 0).requireForAccess(claims()));
        failure(CONTRACT_VIOLATION, () -> new AccountSecurityGate((id,t) -> Optional.of(snapshot(new SecurityIdentity("fixture", "other"), AdmissionState.ADMITTED, revision)), policy, () -> 0).requireForAccess(claims()));
    }
    @Test void invalidNamespaceNeverConsultsPort() {
        AccountSecurityGate gate = new AccountSecurityGate((id,t) -> { fail("Port must not run"); return Optional.empty(); }, policy, () -> 0);
        failure(TOKEN_INVALID, () -> gate.requireForAccess(new TokenAccountClaims(new SecurityIdentity("foreign", "alpha"), revision)));
        failure(TOKEN_INVALID, () -> gate.requireForAccess(null));
    }
    @ParameterizedTest @ValueSource(longs = {100, 101, -1})
    void rejectsLateExactDeadlineOrInvalidElapsedWithoutRetries(long elapsed) {
        AtomicLong nanos = new AtomicLong(); AtomicInteger calls = new AtomicInteger();
        AccountSecurityGate gate = new AccountSecurityGate((id,t) -> {
            calls.incrementAndGet(); nanos.set(elapsed); return Optional.of(snapshot(id, AdmissionState.ADMITTED, revision));
        }, policy, nanos::get);
        failure(DEPENDENCY_UNAVAILABLE, () -> gate.requireForAccess(claims())); assertEquals(1, calls.get());
    }
    @Test void preservesKnownAndUnexpectedFailuresWithoutFallback() {
        AtomicInteger calls = new AtomicInteger();
        SecurityValidationException known = new SecurityValidationException(DEPENDENCY_UNAVAILABLE);
        AccountSecurityGate gate = new AccountSecurityGate((id,t) -> { calls.incrementAndGet(); throw known; }, policy, () -> 0);
        assertSame(known, assertThrows(SecurityValidationException.class, () -> gate.requireForAccess(claims()))); assertEquals(1, calls.get());
        IllegalStateException unexpected = new IllegalStateException("synthetic");
        assertSame(unexpected, assertThrows(IllegalStateException.class, () -> new AccountSecurityGate((id,t) -> { throw unexpected; }, policy, () -> 0).requireForAccess(claims())));
    }
    @Test void budgetConsumedBeforeInvocationDeniesWithoutCalling() {
        AtomicLong nanos = new AtomicLong();
        AccountSecurityGate gate = new AccountSecurityGate((id,t) -> { fail("Must not call"); return Optional.empty(); }, policy, () -> nanos.getAndAdd(100));
        failure(DEPENDENCY_UNAVAILABLE, () -> gate.requireForAccess(claims()));
    }
}
