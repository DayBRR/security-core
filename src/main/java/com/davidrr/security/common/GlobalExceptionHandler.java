package com.davidrr.security.common;

import com.davidrr.security.auth.exception.*;
import com.davidrr.security.ratelimit.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // -------- AUTH: LOGIN --------

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_BAD_CREDENTIALS,
                ErrorMessages.BAD_CREDENTIALS,
                request
        );
    }

    // -------- VALIDATION --------

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .orElse(ErrorMessages.VALIDATION_FAILED);

        return buildError(
                HttpStatus.BAD_REQUEST,
                ErrorCodes.VALIDATION_ERROR,
                message,
                request
        );
    }

    // -------- REFRESH TOKEN --------

    @ExceptionHandler(RefreshTokenMissingException.class)
    public ResponseEntity<ApiError> handleRefreshMissing(
            RefreshTokenMissingException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_REFRESH_MISSING,
                ErrorMessages.REFRESH_MISSING,
                request
        );
    }

    @ExceptionHandler(RefreshTokenInvalidException.class)
    public ResponseEntity<ApiError> handleRefreshInvalid(
            RefreshTokenInvalidException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_REFRESH_INVALID,
                ErrorMessages.REFRESH_INVALID,
                request
        );
    }

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<ApiError> handleRefreshExpired(
            RefreshTokenExpiredException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_REFRESH_EXPIRED,
                ErrorMessages.REFRESH_EXPIRED,
                request
        );
    }

    @ExceptionHandler(RefreshTokenRevokedException.class)
    public ResponseEntity<ApiError> handleRefreshRevoked(
            RefreshTokenRevokedException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_REFRESH_REVOKED,
                ErrorMessages.REFRESH_REVOKED,
                request
        );
    }

    @ExceptionHandler(RefreshTokenReuseException.class)
    public ResponseEntity<ApiError> handleRefreshTokenReuse(
            RefreshTokenReuseException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_REFRESH_REUSED,
                ErrorMessages.REFRESH_REUSED,
                request
        );
    }

    @ExceptionHandler(SessionNotFoundException.class)
    public ResponseEntity<ApiError> handleSessionNotFound(
            SessionNotFoundException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.NOT_FOUND,
                ErrorCodes.AUTH_SESSION_NOT_FOUND,
                ErrorMessages.SESSION_NOT_FOUND,
                request
        );
    }

    @ExceptionHandler(SuspiciousSessionException.class)
    public ResponseEntity<ApiError> handleSuspiciousSession(
            SuspiciousSessionException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.UNAUTHORIZED,
                ErrorCodes.AUTH_SUSPICIOUS_SESSION,
                ErrorMessages.SUSPICIOUS_SESSION,
                request
        );
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiError> handleRateLimitExceeded(
            RateLimitExceededException ex,
            HttpServletRequest request
    ) {
        return buildError(
                HttpStatus.TOO_MANY_REQUESTS,
                ErrorCodes.AUTH_RATE_LIMIT_EXCEEDED,
                ErrorMessages.RATE_LIMIT_EXCEEDED,
                request
        );
    }

    // -------- Helper --------

    private ResponseEntity<ApiError> buildError(
            HttpStatus status,
            String code,
            String message,
            HttpServletRequest request
    ) {
        ApiError body = new ApiError(
                Instant.now(),
                status.value(),
                status.getReasonPhrase(),
                code,
                message,
                request.getRequestURI()
        );

        return ResponseEntity.status(status).body(body);
    }

}