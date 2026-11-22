package com.davidrr.security.spring.account;

import com.davidrr.security.common.ApiError;
import com.davidrr.security.common.ErrorCodes;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import java.io.IOException;
import java.time.Clock;
import java.util.Objects;

/** Opt-in writer for this channel only; never serializes an exception or request data. */
public final class AccountAuthenticationFailureHandler implements AuthenticationEntryPoint, AccessDeniedHandler {
    private final ObjectMapper mapper;
    private final Clock clock;
    public AccountAuthenticationFailureHandler(ObjectMapper mapper, Clock clock) {
        this.mapper = Objects.requireNonNull(mapper);
        this.clock = Objects.requireNonNull(clock);
    }
    public void write(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException {
        if (request.getDispatcherType() == jakarta.servlet.DispatcherType.INCLUDE) throw new IOException("Included request denied");
        if (failure instanceof AuthoritativeAuthenticationServiceException) {
            write(response, 503, "Service Unavailable", AuthoritativeErrorCodes.SECURITY_DEPENDENCY_UNAVAILABLE,
                    "Servicio de seguridad no disponible");
        } else if (failure instanceof BadCredentialsException || failure instanceof InsufficientAuthenticationException) {
            write(response, 401, "Unauthorized", ErrorCodes.AUTH_UNAUTHORIZED, "No autorizado");
        } else {
            writeUnexpectedFailure(request, response);
        }
    }
    public void writeUnexpectedFailure(HttpServletRequest request, HttpServletResponse response) throws IOException {
        write(response, 500, "Internal Server Error", AuthoritativeErrorCodes.SECURITY_INTERNAL_ERROR, "Error interno");
    }
    @Override public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException {
        write(request, response, failure);
    }
    @Override public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException failure) throws IOException {
        if (request.getDispatcherType() == jakarta.servlet.DispatcherType.INCLUDE) throw new IOException("Included request denied");
        write(response, 403, "Forbidden", ErrorCodes.AUTH_FORBIDDEN, "Acceso denegado");
    }
    private void write(HttpServletResponse response, int status, String error, String code, String message) throws IOException {
        if (response.isCommitted()) return;
        response.resetBuffer();
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        if (status == 401) response.setHeader("WWW-Authenticate", "Bearer");
        // A fixed path avoids leaking identifiers or credentials embedded in arbitrary resource paths.
        mapper.writeValue(response.getOutputStream(), new ApiError(clock.instant(), status, error, code, message, "/"));
    }
}
