package com.davidrr.security.auth;

import com.davidrr.security.auth.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

class AuthenticationJsonContractTest {
    private final ObjectMapper mapper = Jackson2ObjectMapperBuilder.json().build();

    @Test
    void requestsKeepJsonNamesValuesAndDeserialization() throws Exception {
        String authJson = "{\"username\":\"synthetic-user\",\"password\":\"synthetic-password\"}";
        AuthRequest auth = mapper.readValue(authJson, AuthRequest.class);
        auth.toString();
        assertEquals("synthetic-user", auth.getUsername());
        assertEquals("synthetic-password", auth.getPassword());
        assertEquals(mapper.readTree(authJson), mapper.valueToTree(auth));

        String registerJson = "{\"username\":\"synthetic-user\",\"email\":\"synthetic@example.invalid\",\"password\":\"synthetic-password\"}";
        RegisterRequest registration = mapper.readValue(registerJson, RegisterRequest.class);
        registration.toString();
        assertEquals("synthetic-user", registration.getUsername());
        assertEquals("synthetic@example.invalid", registration.getEmail());
        assertEquals("synthetic-password", registration.getPassword());
        assertEquals(mapper.readTree(registerJson), mapper.valueToTree(registration));
    }

    @Test
    void authResponseKeepsOnlyTokenIncludingNull() throws Exception {
        AuthResponse response = new AuthResponse("synthetic-access");
        response.toString();
        assertEquals(mapper.readTree("{\"token\":\"synthetic-access\"}"), mapper.valueToTree(response));
        assertEquals(mapper.readTree("{\"token\":null}"), mapper.valueToTree(new AuthResponse(null)));
    }

    @Test
    void recordsKeepComponentJsonAndRoundTrip() throws Exception {
        AuthTokens tokens = new AuthTokens("synthetic-access", "synthetic-refresh");
        RefreshRotationResult rotation = new RefreshRotationResult("synthetic-user", "synthetic-refresh");
        tokens.toString();
        rotation.toString();
        assertEquals(mapper.readTree("{\"accessToken\":\"synthetic-access\",\"refreshToken\":\"synthetic-refresh\"}"), mapper.valueToTree(tokens));
        assertEquals(mapper.readTree("{\"username\":\"synthetic-user\",\"refreshToken\":\"synthetic-refresh\"}"), mapper.valueToTree(rotation));
        assertEquals(tokens, mapper.readValue(mapper.writeValueAsString(tokens), AuthTokens.class));
        assertEquals(rotation, mapper.readValue(mapper.writeValueAsString(rotation), RefreshRotationResult.class));
    }

    @Test
    void standaloneHttpFixtureKeepsAccessInBodyAndRefreshOnlyInCookie() throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new AuthResponseFixture())
                .setMessageConverters(new MappingJackson2HttpMessageConverter(mapper)).build();
        MvcResult result = mvc.perform(get("/test/auth-response")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(result.getResponse().getContentType())));
        String body = result.getResponse().getContentAsString();
        assertEquals(mapper.readTree("{\"token\":\"synthetic-access\"}"), mapper.readTree(body));
        assertFalse(body.contains("synthetic-refresh"));
        assertFalse(body.contains("[REDACTED]"));
        String cookie = result.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertNotNull(cookie);
        assertTrue(cookie.contains("fixture_refresh=synthetic-refresh"));
        assertTrue(cookie.contains("HttpOnly"));
        assertTrue(cookie.contains("Secure"));
        assertTrue(cookie.contains("SameSite=Lax"));
        assertTrue(cookie.contains("Path=/test"));
        assertFalse(cookie.contains("[REDACTED]"));
    }

    // Test-only transport composition; no production endpoint or Grind dependency.
    @RestController
    static class AuthResponseFixture {
        @GetMapping("/test/auth-response")
        public ResponseEntity<AuthResponse> response() {
            AuthTokens tokens = new AuthTokens("synthetic-access", "synthetic-refresh");
            tokens.toString();
            AuthResponse body = new AuthResponse(tokens.accessToken());
            body.toString();
            ResponseCookie cookie = ResponseCookie.from("fixture_refresh", tokens.refreshToken())
                    .httpOnly(true).secure(true).sameSite("Lax").path("/test").build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(body);
        }
    }
}
