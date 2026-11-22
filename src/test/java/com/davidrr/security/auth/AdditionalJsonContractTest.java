package com.davidrr.security.auth;

import com.davidrr.security.auth.dto.SessionResponse;
import com.davidrr.security.common.ApiError;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AdditionalJsonContractTest {
    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final Instant TIME = Instant.parse("2026-01-02T03:04:05Z");

    @Test
    void sessionResponseKeepsTransportPropertiesTypesAndValues() throws Exception {
        SessionResponse value = new SessionResponse(37L, TIME, TIME.plusSeconds(1), TIME.plusSeconds(60),
                "192.0.2.1", "synthetic-agent", "synthetic-device", true);
        JsonNode json = mapper.readTree(mapper.writeValueAsBytes(value));
        fields(json, "id", "createdAt", "lastUsedAt", "expiresAt", "ip", "userAgent", "device", "current");
        assertTrue(json.get("id").isIntegralNumber());
        assertEquals(37L, json.get("id").longValue());
        instant(json, "createdAt", TIME);
        instant(json, "lastUsedAt", TIME.plusSeconds(1));
        instant(json, "expiresAt", TIME.plusSeconds(60));
        text(json, "ip", "192.0.2.1");
        text(json, "userAgent", "synthetic-agent");
        text(json, "device", "synthetic-device");
        assertTrue(json.get("current").isBoolean());
        assertTrue(json.get("current").booleanValue());
        assertEquals(value, mapper.treeToValue(json, SessionResponse.class));
    }

    @Test
    void sessionResponsePreservesNullableComponentsAndFalse() throws Exception {
        SessionResponse value = new SessionResponse(null, null, null, null, null, null, null, false);
        JsonNode json = mapper.readTree(mapper.writeValueAsBytes(value));
        fields(json, "id", "createdAt", "lastUsedAt", "expiresAt", "ip", "userAgent", "device", "current");
        for (String name : Set.of("id", "createdAt", "lastUsedAt", "expiresAt", "ip", "userAgent", "device"))
            assertTrue(json.get(name).isNull(), name);
        assertTrue(json.get("current").isBoolean());
        assertFalse(json.get("current").booleanValue());
        assertEquals(value, mapper.treeToValue(json, SessionResponse.class));
    }

    @Test
    void apiErrorKeepsTransportPropertiesTypesAndValues() throws Exception {
        ApiError value = new ApiError(TIME, 401, "Unauthorized", "SYNTHETIC_CODE", "synthetic-message", "/fixture/resource");
        JsonNode json = mapper.readTree(mapper.writeValueAsBytes(value));
        fields(json, "timestamp", "status", "error", "code", "message", "path");
        instant(json, "timestamp", TIME);
        assertTrue(json.get("status").isIntegralNumber());
        assertEquals(401, json.get("status").intValue());
        text(json, "error", "Unauthorized");
        text(json, "code", "SYNTHETIC_CODE");
        text(json, "message", "synthetic-message");
        text(json, "path", "/fixture/resource");
        assertEquals(value, mapper.treeToValue(json, ApiError.class));
    }

    @Test
    void apiErrorPreservesNullableComponentsAndNumericZero() throws Exception {
        ApiError value = new ApiError(null, 0, null, null, null, null);
        JsonNode json = mapper.readTree(mapper.writeValueAsBytes(value));
        fields(json, "timestamp", "status", "error", "code", "message", "path");
        for (String name : Set.of("timestamp", "error", "code", "message", "path")) assertTrue(json.get(name).isNull(), name);
        assertTrue(json.get("status").isIntegralNumber());
        assertEquals(0, json.get("status").intValue());
        assertEquals(value, mapper.treeToValue(json, ApiError.class));
    }

    private static void fields(JsonNode json, String... names) {
        Set<String> actual = new HashSet<>();
        json.fieldNames().forEachRemaining(actual::add);
        assertEquals(Set.of(names), actual);
    }

    private static void text(JsonNode json, String name, String expected) {
        assertTrue(json.get(name).isTextual(), name);
        assertEquals(expected, json.get(name).textValue());
    }

    private static void instant(JsonNode json, String name, Instant expected) {
        assertTrue(json.get(name).isTextual(), name);
        assertEquals(expected, Instant.parse(json.get(name).textValue()));
    }
}
