package com.davidrr.security.account;

import java.util.Objects;

/** Fixed diagnostic vocabulary; never retains input, provider messages, or external causes. */
public final class SecurityValidationException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final SecurityValidationFailure failure;
    public SecurityValidationException(SecurityValidationFailure failure) {
        super("Security validation failed: " + Objects.requireNonNull(failure), null);
        this.failure = failure;
    }
    public SecurityValidationFailure failure() { return failure; }
}
