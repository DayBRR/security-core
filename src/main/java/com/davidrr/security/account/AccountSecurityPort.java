package com.davidrr.security.account;

import java.time.Duration;
import java.util.Optional;

/**
 * Linearizable, coherent lookup by stable identity. The adapter must bound the entire call
 * (pool, I/O, retries and decoding) by timeout and release resources on failure. Empty means
 * authoritative absence; known infrastructure failures use DEPENDENCY_UNAVAILABLE.
 */
public interface AccountSecurityPort {
    Optional<AccountSecuritySnapshot> readCurrent(SecurityIdentity identity, Duration timeout);
}
