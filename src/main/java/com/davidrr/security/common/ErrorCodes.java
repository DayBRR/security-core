package com.davidrr.security.common;

public final class ErrorCodes {

    private ErrorCodes() {}

    // --- AUTH ---
    public static final String AUTH_BAD_CREDENTIALS = "AUTH_BAD_CREDENTIALS";
    public static final String AUTH_UNAUTHORIZED = "AUTH_UNAUTHORIZED";
    public static final String AUTH_FORBIDDEN = "AUTH_FORBIDDEN";

    // --- REFRESH TOKEN ---
    public static final String AUTH_REFRESH_MISSING = "AUTH_REFRESH_MISSING";
    public static final String AUTH_REFRESH_INVALID = "AUTH_REFRESH_INVALID";
    public static final String AUTH_REFRESH_EXPIRED = "AUTH_REFRESH_EXPIRED";
    public static final String AUTH_REFRESH_REVOKED = "AUTH_REFRESH_REVOKED";
    public static final String AUTH_REFRESH_REUSED = "AUTH_REFRESH_REUSED";

    // --- SESSION ---
    public static final String AUTH_SESSION_NOT_FOUND = "AUTH_SESSION_NOT_FOUND";
    public static final String AUTH_SUSPICIOUS_SESSION = "AUTH_SUSPICIOUS_SESSION";

    // --- RATE_LIMIT ---
    public static final String AUTH_RATE_LIMIT_EXCEEDED = "AUTH_RATE_LIMIT_EXCEEDED";

    // --- VALIDATION ---
    public static final String VALIDATION_ERROR = "VALIDATION_ERROR";

    // --- TOKEN ---
    public static final String TOKEN_EXPIRED = "TOKEN_EXPIRED";
    public static final String TOKEN_INVALID = "TOKEN_INVALID";
}
