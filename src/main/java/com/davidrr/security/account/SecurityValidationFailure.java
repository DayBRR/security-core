package com.davidrr.security.account;

public enum SecurityValidationFailure {
    TOKEN_INVALID, IDENTITY_ABSENT, ACCOUNT_NOT_ADMITTED,
    REVISION_MISMATCH, DEPENDENCY_UNAVAILABLE, CONTRACT_VIOLATION
}
