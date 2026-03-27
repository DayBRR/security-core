package com.davidrr.security.common;

public final class ErrorMessages {

    private ErrorMessages() {}

    // --- AUTH ---
    public static final String BAD_CREDENTIALS = "Credenciales erróneas";
    public static final String UNAUTHORIZED = "No autorizado";
    public static final String FORBIDDEN = "Acceso denegado";

    // --- VALIDATION ---
    public static final String VALIDATION_FAILED = "Validación fallida";

    // --- REFRESH TOKEN ---
    public static final String REFRESH_MISSING = "Refresh token no encontrado";
    public static final String REFRESH_INVALID = "Refresh token inválido";
    public static final String REFRESH_EXPIRED = "Refresh token expirado";
    public static final String REFRESH_REVOKED = "Refresh token revocado";
    public static final String REFRESH_REUSED = "Se ha detectado reutilización de refresh token";

    // --- SESSION ---
    public static final String SESSION_NOT_FOUND = "Sesión no encontrada";
    public static final String SUSPICIOUS_SESSION = "Sesión sospechosa detectada";

    // --- RATE_LIMIT ---
    public static final String RATE_LIMIT_EXCEEDED = "Demasiados intentos. Inténtalo de nuevo más tarde.";

}
