package com.davidrr.security.auth;

import com.davidrr.security.auth.dto.*;
import com.davidrr.security.auth.session.model.RefreshSession;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PublicSurfaceCompatibilityTest {
    @Test
    void constructorsAndRecordComponentsKeepTheirBaselineShape() throws Exception {
        assertTrue(Modifier.isPublic(AuthRequest.class.getConstructor().getModifiers()));
        AuthRequest.class.getConstructor(String.class, String.class);
        RegisterRequest.class.getConstructor();
        AuthResponse.class.getConstructor(String.class);
        assertThrows(NoSuchMethodException.class, () -> AuthResponse.class.getMethod("setToken", String.class));
        assertTrue(Modifier.isFinal(AuthResponse.class.getDeclaredField("token").getModifiers()));
        verifyRecord(AuthTokens.class, "accessToken", "refreshToken");
        verifyRecord(RefreshRotationResult.class, "username", "refreshToken");

        Class<?>[] sessionParameters = {Long.class, String.class, String.class, Instant.class,
                Instant.class, Instant.class, boolean.class, Instant.class,
                String.class, String.class, String.class, String.class};
        assertEquals(0, RefreshSession.class.getDeclaredConstructor(sessionParameters).getModifiers());
        assertThrows(NoSuchMethodException.class, () -> RefreshSession.class.getConstructor());
        Class<?> builder = RefreshSession.RefreshSessionBuilder.class;
        assertTrue(Modifier.isPublic(builder.getModifiers()));
        assertTrue(Modifier.isStatic(builder.getModifiers()));
        assertEquals(0, builder.getDeclaredConstructor().getModifiers());
        assertEquals(builder, RefreshSession.class.getMethod("builder").getReturnType());
        assertEquals(RefreshSession.class, builder.getMethod("build").getReturnType());
    }

    @Test
    void beanAccessorsAndAllBuilderMethodsKeepTypesAndVisibility() throws Exception {
        verifyProperty(AuthRequest.class, "username", String.class);
        verifyProperty(AuthRequest.class, "password", String.class);
        verifyProperty(RegisterRequest.class, "username", String.class);
        verifyProperty(RegisterRequest.class, "email", String.class);
        verifyProperty(RegisterRequest.class, "password", String.class);
        assertEquals(String.class, AuthResponse.class.getMethod("getToken").getReturnType());
        String[] fields = {"id", "username", "tokenHash", "createdAt", "expiresAt", "lastUsedAt",
                "revoked", "revokedAt", "revocationReason", "replacedByTokenHash", "ip", "userAgent"};
        Class<?>[] types = {Long.class, String.class, String.class, Instant.class, Instant.class,
                Instant.class, boolean.class, Instant.class, String.class, String.class, String.class, String.class};
        for (int i = 0; i < fields.length; i++) {
            verifyProperty(RefreshSession.class, fields[i], types[i]);
            assertEquals(RefreshSession.RefreshSessionBuilder.class,
                    RefreshSession.RefreshSessionBuilder.class.getMethod(fields[i], types[i]).getReturnType());
        }
        for (Class<?> type : new Class<?>[]{AuthRequest.class, RegisterRequest.class, AuthResponse.class, RefreshSession.class}) {
            assertTrue(Modifier.isProtected(type.getDeclaredMethod("canEqual", Object.class).getModifiers()));
            assertEquals(boolean.class, type.getMethod("equals", Object.class).getReturnType());
            assertEquals(int.class, type.getMethod("hashCode").getReturnType());
            assertEquals(Modifier.PUBLIC, type.getDeclaredMethod("toString").getModifiers());
        }
        assertEquals(Modifier.PUBLIC, RefreshSession.RefreshSessionBuilder.class.getDeclaredMethod("toString").getModifiers());
    }

    @Test
    void equalityAndHashCodeStillUseOriginalValuesAfterRendering() {
        AuthRequest request = new AuthRequest("synthetic-user", "synthetic-password");
        verifyEquality(request, new AuthRequest("synthetic-user", "synthetic-password"),
                new AuthRequest("synthetic-user", "synthetic-other-password"));
        verifyEquality(registration("synthetic-password"), registration("synthetic-password"), registration("synthetic-other-password"));
        verifyEquality(new AuthResponse("synthetic-access"), new AuthResponse("synthetic-access"), new AuthResponse("synthetic-other-access"));
        AuthTokens tokens = new AuthTokens("synthetic-access", "synthetic-refresh");
        verifyEquality(tokens, new AuthTokens(tokens.accessToken(), tokens.refreshToken()),
                new AuthTokens("synthetic-access", "synthetic-other-refresh"));
        assertNotEquals(tokens, new AuthTokens("synthetic-other-access", "synthetic-refresh"));
        RefreshRotationResult rotation = new RefreshRotationResult("synthetic-user", "synthetic-refresh");
        verifyEquality(rotation, new RefreshRotationResult(rotation.username(), rotation.refreshToken()),
                new RefreshRotationResult("synthetic-user", "synthetic-other-refresh"));
        RefreshSession session = RefreshSession.builder().username("synthetic-user").tokenHash("synthetic-hash").build();
        verifyEquality(session, RefreshSession.builder().username("synthetic-user").tokenHash("synthetic-hash").build(),
                RefreshSession.builder().username("synthetic-user").tokenHash("synthetic-other-hash").build());
        session.setTokenHash("synthetic-new-hash");
        session.toString();
        assertEquals("synthetic-new-hash", session.getTokenHash());
    }

    private static void verifyRecord(Class<?> type, String... names) throws Exception {
        assertTrue(type.isRecord());
        assertTrue(Modifier.isFinal(type.getModifiers()));
        assertArrayEquals(names, Arrays.stream(type.getRecordComponents()).map(RecordComponent::getName).toArray(String[]::new));
        for (RecordComponent component : type.getRecordComponents()) {
            assertEquals(String.class, component.getType());
            assertEquals(String.class, component.getAccessor().getReturnType());
        }
        type.getConstructor(String.class, String.class);
        assertEquals(Modifier.PUBLIC | Modifier.FINAL, type.getDeclaredMethod("toString").getModifiers());
    }

    private static void verifyProperty(Class<?> type, String field, Class<?> valueType) throws Exception {
        String suffix = Character.toUpperCase(field.charAt(0)) + field.substring(1);
        assertEquals(valueType, type.getMethod((valueType == boolean.class ? "is" : "get") + suffix).getReturnType());
        assertEquals(void.class, type.getMethod("set" + suffix, valueType).getReturnType());
    }

    private static RegisterRequest registration(String password) {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("synthetic-user");
        request.setEmail("synthetic@example.invalid");
        request.setPassword(password);
        return request;
    }

    private static void verifyEquality(Object value, Object equal, Object different) {
        int before = value.hashCode();
        value.toString();
        equal.toString();
        assertEquals(equal, value);
        assertEquals(value, equal);
        assertEquals(before, value.hashCode());
        assertEquals(value.hashCode(), equal.hashCode());
        assertNotEquals(different, value);
    }
}
