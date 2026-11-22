package com.davidrr.security.account;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;
import static com.davidrr.security.account.SecurityValidationFailure.*;

/** One read per attempt, without retries/cache. Cannot interrupt a blocked adapter call. */
public final class AccountSecurityGate {
    private final AccountSecurityPort accounts;
    private final AccountSecurityPolicy policy;
    private final LongSupplier monotonicNanos;

    public AccountSecurityGate(AccountSecurityPort accounts, AccountSecurityPolicy policy) {
        this(accounts, policy, System::nanoTime);
    }
    AccountSecurityGate(AccountSecurityPort accounts, AccountSecurityPolicy policy, LongSupplier monotonicNanos) {
        this.accounts = Objects.requireNonNull(accounts); this.policy = Objects.requireNonNull(policy);
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos);
    }
    public String securityContextId() { return policy.securityContextId(); }

    public AccountSecuritySnapshot requireForAccess(TokenAccountClaims claims) {
        if (claims == null) throw new SecurityValidationException(TOKEN_INVALID);
        if (!policy.acceptedNamespaces().contains(claims.identity().namespace())) throw new SecurityValidationException(TOKEN_INVALID);
        long start = monotonicNanos.getAsLong();
        long budget = policy.lookupTimeout().toNanos();
        long elapsed = monotonicNanos.getAsLong() - start;
        if (elapsed < 0 || elapsed >= budget) throw new SecurityValidationException(DEPENDENCY_UNAVAILABLE);
        Optional<AccountSecuritySnapshot> result = accounts.readCurrent(claims.identity(), Duration.ofNanos(budget - elapsed));
        elapsed = monotonicNanos.getAsLong() - start;
        if (elapsed < 0 || elapsed >= budget) throw new SecurityValidationException(DEPENDENCY_UNAVAILABLE);
        if (result == null) throw new SecurityValidationException(CONTRACT_VIOLATION);
        AccountSecuritySnapshot snapshot = result.orElseThrow(() -> new SecurityValidationException(IDENTITY_ABSENT));
        if (!claims.identity().equals(snapshot.identity())) throw new SecurityValidationException(CONTRACT_VIOLATION);
        if (snapshot.admission() != AdmissionState.ADMITTED) throw new SecurityValidationException(ACCOUNT_NOT_ADMITTED);
        if (!claims.revision().equals(snapshot.revision())) throw new SecurityValidationException(REVISION_MISMATCH);
        return snapshot;
    }
}
