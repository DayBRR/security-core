package com.davidrr.security.common;

import com.davidrr.security.auth.exception.*;
import com.davidrr.security.ratelimit.exception.RateLimitExceededException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** HTTP-01: exception-to-response mapping; complete JSON shape is owned by 02A. */
class HttpErrorContractTest {
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    record Failure(RuntimeException exception, int status, String code, String message) { }

    static Stream<Failure> failures() {
        return Stream.of(
                new Failure(new BadCredentialsException("synthetic-private-detail"), 401, ErrorCodes.AUTH_BAD_CREDENTIALS, ErrorMessages.BAD_CREDENTIALS),
                new Failure(new RefreshTokenMissingException(), 401, ErrorCodes.AUTH_REFRESH_MISSING, ErrorMessages.REFRESH_MISSING),
                new Failure(new RefreshTokenInvalidException(), 401, ErrorCodes.AUTH_REFRESH_INVALID, ErrorMessages.REFRESH_INVALID),
                new Failure(new RefreshTokenExpiredException(), 401, ErrorCodes.AUTH_REFRESH_EXPIRED, ErrorMessages.REFRESH_EXPIRED),
                new Failure(new RefreshTokenRevokedException(), 401, ErrorCodes.AUTH_REFRESH_REVOKED, ErrorMessages.REFRESH_REVOKED),
                new Failure(new RefreshTokenReuseException(), 401, ErrorCodes.AUTH_REFRESH_REUSED, ErrorMessages.REFRESH_REUSED),
                new Failure(new SessionNotFoundException(), 404, ErrorCodes.AUTH_SESSION_NOT_FOUND, ErrorMessages.SESSION_NOT_FOUND),
                new Failure(new SuspiciousSessionException(), 401, ErrorCodes.AUTH_SUSPICIOUS_SESSION, ErrorMessages.SUSPICIOUS_SESSION),
                new Failure(new RateLimitExceededException(), 429, ErrorCodes.AUTH_RATE_LIMIT_EXCEEDED, ErrorMessages.RATE_LIMIT_EXCEEDED));
    }

    @ParameterizedTest
    @MethodSource("failures")
    void mvcAdviceMapsEachLegacyException(Failure failure) throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ThrowingFixture(failure.exception()))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        MockHttpServletResponse response = mvc.perform(get("/fixture/error")).andExpect(status().is(failure.status()))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)).andReturn().getResponse();
        JsonNode body = mapper.readTree(response.getContentAsByteArray());
        assertEquals(failure.status(), body.path("status").intValue());
        assertEquals(failure.code(), body.path("code").textValue());
        assertEquals(failure.message(), body.path("message").textValue());
        assertEquals("/fixture/error", body.path("path").textValue());
        assertFalse(response.getContentAsString().contains("synthetic-private-detail"));
    }

    @Test
    void beanValidationFailureUses400AndValidationMapping() throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ValidationFixture())
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        MockHttpServletResponse response = mvc.perform(post("/fixture/validation").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"value\":\"\"}"))
                .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn().getResponse();
        JsonNode body = mapper.readTree(response.getContentAsByteArray());
        assertEquals(ErrorCodes.VALIDATION_ERROR, body.path("code").textValue());
        assertEquals("value: required", body.path("message").textValue());
        assertEquals("/fixture/validation", body.path("path").textValue());
    }

    @Test
    void validationWithoutFieldErrorsUsesFallbackMessage() {
        BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new Object(), "fixture");
        MethodArgumentNotValidException failure = new MethodArgumentNotValidException(null, binding);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/fixture/validation");
        var response = new GlobalExceptionHandler().handleValidation(failure, request);
        assertEquals(400, response.getStatusCode().value());
        assertEquals(ErrorMessages.VALIDATION_FAILED, response.getBody().message());
    }

    @Test
    void entryPointWrites401JsonWithoutRedirectOrRawExceptionMessage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/fixture/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestAuthenticationEntryPoint(mapper).commence(request, response, new BadCredentialsException("synthetic-private-detail"));
        checkBoundary(response, 401, ErrorCodes.AUTH_UNAUTHORIZED, ErrorMessages.UNAUTHORIZED);
        assertNull(response.getRedirectedUrl());
    }

    @Test
    void accessDeniedWrites403JsonWithoutRawExceptionMessage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/fixture/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RestAccessDeniedHandler(mapper).handle(request, response, new AccessDeniedException("synthetic-private-detail"));
        checkBoundary(response, 403, ErrorCodes.AUTH_FORBIDDEN, ErrorMessages.FORBIDDEN);
    }

    private void checkBoundary(MockHttpServletResponse response, int status, String code, String message) throws Exception {
        assertEquals(status, response.getStatus());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(response.getContentType())));
        JsonNode body = mapper.readTree(response.getContentAsByteArray());
        assertEquals(status, body.path("status").intValue());
        assertEquals(code, body.path("code").textValue());
        assertEquals(message, body.path("message").textValue());
        assertEquals("/fixture/protected", body.path("path").textValue());
        assertFalse(response.getContentAsString().contains("synthetic-private-detail"));
    }

    @RestController
    static class ThrowingFixture {
        private final RuntimeException failure;
        ThrowingFixture(RuntimeException failure) { this.failure = failure; }
        @GetMapping("/fixture/error")
        public void fail() { throw failure; }
    }

    @RestController
    static class ValidationFixture {
        @PostMapping("/fixture/validation")
        public void validate(@Valid @RequestBody Input input) { }
    }

    record Input(@NotBlank(message = "required") String value) { }
}
