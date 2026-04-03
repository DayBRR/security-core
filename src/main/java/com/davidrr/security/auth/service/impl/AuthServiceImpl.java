package com.davidrr.security.auth.service.impl;

import com.davidrr.security.audit.SecurityAuditContext;
import com.davidrr.security.audit.SecurityAuditService;
import com.davidrr.security.audit.SecurityEventType;
import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.event.UserRegisteredEvent;
import com.davidrr.security.auth.exception.RefreshTokenExpiredException;
import com.davidrr.security.auth.exception.RefreshTokenInvalidException;
import com.davidrr.security.auth.exception.RefreshTokenReuseException;
import com.davidrr.security.auth.exception.SuspiciousSessionException;
import com.davidrr.security.auth.port.UserProvider;
import com.davidrr.security.auth.port.UserRegistrationPort;
import com.davidrr.security.auth.service.AuthService;
import com.davidrr.security.auth.session.model.RefreshSession;
import com.davidrr.security.auth.session.service.RefreshTokenService;
import com.davidrr.security.jwt.JwtService;
import com.davidrr.security.ratelimit.config.RateLimitProperties;
import com.davidrr.security.ratelimit.service.RateLimiterService;
import com.davidrr.security.ratelimit.util.RateLimitKeyFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserProvider userProvider;

    private final RateLimiterService rateLimiterService;
    private final RateLimitKeyFactory rateLimitKeyFactory;

    private final SecurityAuditService securityAuditService;

    private final UserRegistrationPort userRegistrationPort;
    private final ApplicationEventPublisher eventPublisher;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public AuthTokens register(RegisterRequest request, SessionFingerprint fingerprint) {

        // Registrar usuario (delegado al dominio/app)
        UserRegistrationPort.RegisteredUser registeredUser =
                userRegistrationPort.register(
                        request.getUsername(),
                        passwordEncoder.encode(request.getPassword())
                );

        // Publicar evento
        eventPublisher.publishEvent(
                new UserRegisteredEvent(
                        registeredUser.id(),
                        registeredUser.username()
                )
        );

        // Cargar usuario para generar tokens
        UserDetails userDetails = userProvider.loadUserByUsername(registeredUser.username());

        String accessToken = jwtService.generateToken(userDetails);

        String refreshToken = refreshTokenService.createRefreshToken(
                userDetails.getUsername(),
                fingerprint
        );

        // Auditoría
        securityAuditService.log(
                SecurityEventType.REGISTER_SUCCESS,
                SecurityAuditContext.of(
                        userDetails.getUsername(),
                        fingerprint.ip(),
                        fingerprint.userAgent(),
                        null,
                        null,
                        "User registered successfully"
                )
        );

        return new AuthTokens(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public AuthTokens login(AuthRequest request, SessionFingerprint fingerprint) {
        String key = rateLimitKeyFactory.loginKey(fingerprint);

        try {
            rateLimiterService.check(RateLimitProperties.Bucket.LOGIN, key);
        } catch (RuntimeException ex) {
            securityAuditService.log(
                    SecurityEventType.RATE_LIMIT_EXCEEDED,
                    SecurityAuditContext.of(
                            request.getUsername(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            "LOGIN_RATE_LIMIT",
                            "Login rate limit exceeded"
                    )
            );
            throw ex;
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            refreshTokenService.cleanupExpired();

            String accessToken = jwtService.generateToken(userDetails);
            String refreshToken = refreshTokenService.createRefreshToken(
                    userDetails.getUsername(),
                    fingerprint
            );

            rateLimiterService.onSuccess(RateLimitProperties.Bucket.LOGIN, key);

            securityAuditService.log(
                    SecurityEventType.LOGIN_SUCCESS,
                    SecurityAuditContext.of(
                            userDetails.getUsername(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            null,
                            "Login successful"
                    )
            );

            return new AuthTokens(accessToken, refreshToken);

        } catch (DisabledException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.LOGIN, key);

            securityAuditService.log(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityAuditContext.of(
                            request.getUsername(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            "USER_DISABLED",
                            "Login failed because user is disabled"
                    )
            );

            throw ex;

        } catch (BadCredentialsException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.LOGIN, key);

            securityAuditService.log(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityAuditContext.of(
                            request.getUsername(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            "BAD_CREDENTIALS",
                            "Invalid username or password"
                    )
            );

            throw ex;
        }
    }

    @Override
    @Transactional
    public AuthTokens refresh(String refreshToken, SessionFingerprint fingerprint) {
        String key = rateLimitKeyFactory.refreshKey(fingerprint);

        try {
            rateLimiterService.check(RateLimitProperties.Bucket.REFRESH, key);
        } catch (RuntimeException ex) {
            securityAuditService.log(
                    SecurityEventType.RATE_LIMIT_EXCEEDED,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            "REFRESH_RATE_LIMIT",
                            "Refresh rate limit exceeded"
                    )
            );
            throw ex;
        }

        try {
            RefreshRotationResult rotation = refreshTokenService.rotate(refreshToken, fingerprint);

            UserDetails userDetails = userProvider.loadUserByUsername(rotation.username());
            String newAccessToken = jwtService.generateToken(userDetails);

            rateLimiterService.onSuccess(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.REFRESH_SUCCESS,
                    SecurityAuditContext.of(
                            rotation.username(),
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            null,
                            "Refresh successful"
                    )
            );

            return new AuthTokens(newAccessToken, rotation.refreshToken());

        } catch (RefreshTokenInvalidException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.REFRESH_INVALID_TOKEN,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            ex.getClass().getSimpleName(),
                            "Refresh failed because token is invalid"
                    )
            );

            throw ex;

        } catch (RefreshTokenExpiredException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.REFRESH_TOKEN_EXPIRED,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            ex.getClass().getSimpleName(),
                            "Refresh failed because token is expired"
                    )
            );

            throw ex;

        } catch (RefreshTokenReuseException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            ex.getClass().getSimpleName(),
                            "Refresh failed because token reuse was detected"
                    )
            );

            throw ex;

        } catch (SuspiciousSessionException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.SUSPICIOUS_SESSION_DETECTED,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            ex.getClass().getSimpleName(),
                            "Refresh failed because session was marked as suspicious"
                    )
            );

            throw ex;

        } catch (RuntimeException ex) {
            rateLimiterService.onFailure(RateLimitProperties.Bucket.REFRESH, key);

            securityAuditService.log(
                    SecurityEventType.REFRESH_FAILURE,
                    SecurityAuditContext.of(
                            null,
                            fingerprint.ip(),
                            fingerprint.userAgent(),
                            null,
                            ex.getClass().getSimpleName(),
                            "Refresh failed"
                    )
            );

            throw ex;
        }
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }

    @Override
    @Transactional
    public void logoutAll(String refreshToken) {
        RefreshSession session = refreshTokenService.findSessionByToken(refreshToken);
        refreshTokenService.revokeAll(session.getUsername());
    }

    @Override
    @Transactional(readOnly = true)
    public List<SessionResponse> getSessions(String refreshToken) {
        return refreshTokenService.getActiveSessions(refreshToken);
    }

    @Override
    @Transactional
    public void revokeSession(String refreshToken, Long sessionId) {
        refreshTokenService.revokeSession(refreshToken, sessionId);
    }
}