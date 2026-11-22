package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class JwtCryptographicVerifierTest {
    static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    static final Instant NOW = Instant.ofEpochSecond(1900000100);
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final String HEADER = "{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}";
    static final String BODY = "{\"iss\":\"issuer-fixture\",\"aud\":\"resource-fixture\",\"sub\":\"opaque:alpha\",\"identity_namespace\":\"fixture\","
            + "\"security_revision_scheme\":\"counter-v1\",\"security_revision\":\"7\",\"token_use\":\"access\",\"iat\":1900000000,\"exp\":1900000900,\"jti\":\"fixture-1\"}";
    static JwtVerificationPolicy policy(String context) {
        return new JwtVerificationPolicy(context, "issuer-fixture", Set.of("resource-fixture"), Set.of("HS256"), Duration.ZERO,
                Duration.ofMinutes(15), StrictJwtJsonTest.LIMITS);
    }
    static JwtCryptographicVerifier verifier(Clock clock) {
        return new JwtCryptographicVerifier(policy("ctx"), (id,alg) -> new SecretKeySpec(KEY, "HmacSHA256"), clock);
    }
    static String sign(String header, String payload) { return sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8), KEY); }
    static String sign(byte[] header, byte[] payload, byte[] key) {
        try {
            Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
            String input = b64.encodeToString(header) + "." + b64.encodeToString(payload);
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return input + "." + b64.encodeToString(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception failure) { throw new IllegalStateException("Synthetic signing failure"); }
    }
    static Stream<String> badHeaders() {
        return Stream.of(HEADER.replace("HS256", "none"), HEADER.replace("HS256", "HS384"), HEADER.replace("HS256", "RS256"),
                HEADER.replace("at+jwt", "JWT"), "{\"alg\":\"HS256\"}", "{\"typ\":\"at+jwt\"}",
                HEADER.replace("}", ",\"alg\":\"HS256\"}"), HEADER.replace("}", ",\"\\u0061lg\":\"HS256\"}"),
                HEADER.replace("}", ",\"zip\":\"DEF\"}"), HEADER.replace("}", ",\"crit\":[]}"), HEADER.replace("}", ",\"b64\":false}"),
                HEADER.replace("}", ",\"jku\":\"https://key.example.invalid\"}"), HEADER.replace("}", ",\"x5u\":\"https://key.example.invalid\"}"),
                HEADER.replace("}", ",\"jwk\":{}}"), HEADER.replace("}", ",\"kid\":null}"), HEADER.replace("}", ",\"kid\":\"../key\"}"),
                HEADER.replace("}", ",\"kid\":\"" + "x".repeat(129) + "\"}"), "[]", HEADER + "{}", "\uFEFF" + HEADER);
    }
    static Stream<String> badPayloads() {
        List<String> bad = new ArrayList<>();
        for (String name : List.of("iss","aud","sub","identity_namespace","security_revision_scheme","security_revision","token_use","iat","exp","jti")) {
            // Build missing fields without a Map serializer so raw duplicate tests remain meaningful.
            String fragment = switch (name) {
                case "iat" -> "\"iat\":1900000000,"; case "exp" -> "\"exp\":1900000900,";
                case "jti" -> ",\"jti\":\"fixture-1\"";
                default -> "\"" + name + "\":\"" + Map.of("iss","issuer-fixture","aud","resource-fixture","sub","opaque:alpha", "identity_namespace","fixture", "security_revision_scheme","counter-v1","security_revision","7","token_use","access").get(name) + "\",";
            };
            bad.add(BODY.replace(fragment, ""));
        }
        bad.addAll(List.of(BODY.replace("issuer-fixture","foreign"), BODY.replace("resource-fixture","foreign"),
                BODY.replace("\"resource-fixture\"", "[\"resource-fixture\"]"), BODY.replace("\"access\"","\"refresh\""),
                BODY.replace("1900000900", "1900000100"), BODY.replace("1900000900", "1900000000"), BODY.replace("1900000900", "1900001001"),
                BODY.replace("1900000000", "1900000200"), BODY.replace("1900000900", "\"1900000900\""),
                BODY.replace("1900000900", "1900000900.0"), BODY.replace("1900000900", "1900000900e0"),
                BODY.replace("1900000900", "253402300800"), BODY.replace("1900000000", "-0"),
                BODY.replace("}", ",\"nbf\":1900000200}"), BODY.replace("}", ",\"nbf\":1900000900}"), BODY.replace("}", ",\"nbf\":null}"),
                BODY.replace("}", ",\"roles\":[\"scope:root\"]}"), BODY.replace("}", ",\"exp\":1900000900}"),
                BODY.replace("}", ",\"\\u0065xp\":1900000900}"), BODY + "{}", "\uFEFF" + BODY,
                BODY.replace("\"fixture-1\"", "null"), BODY.replace("\"opaque:alpha\"", "42")));
        return bad.stream();
    }
    @ParameterizedTest @MethodSource("badHeaders") void rejectsRawAdversarialHeaders(String header) { invalid(sign(header, BODY)); }
    @ParameterizedTest @MethodSource("badPayloads") void rejectsRawAdversarialPayloads(String body) { invalid(sign(HEADER, body)); }
    private static void invalid(String token) {
        SecurityValidationException failure = assertThrows(SecurityValidationException.class, () -> verifier(CLOCK).verify(token));
        assertEquals(SecurityValidationFailure.TOKEN_INVALID, failure.failure()); assertNull(failure.getCause());
    }
    @Test void validOriginalSegmentsAndStrictHook() {
        VerifiedJwtClaims claims = verifier(CLOCK).verify(sign(HEADER, BODY));
        assertEquals("ctx", claims.securityContextId()); assertEquals("opaque:alpha", claims.claims().get("sub"));
        assertThrows(UnsupportedOperationException.class, () -> claims.claims().put("sub", "other"));
        assertEquals("VerifiedJwtClaims[REDACTED]", claims.toString());
        // JJWT heuristically treats this as plaintext; strict preflight and original JWS still apply.
        assertDoesNotThrow(() -> verifier(CLOCK).verify(sign(" " + HEADER + " ", " " + BODY + " ")));
    }
    @Test void signaturesCanonicalBase64AndUtf8AreChecked() {
        String valid = sign(HEADER, BODY);
        invalid(sign(HEADER.getBytes(StandardCharsets.UTF_8), BODY.getBytes(StandardCharsets.UTF_8), new byte[32]));
        invalid(valid + "="); invalid(" " + valid); invalid(valid + ".x"); invalid("..x");
        String[] parts = valid.split("\\.");
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int last = alphabet.indexOf(parts[2].charAt(parts[2].length() - 1));
        invalid(parts[0] + "." + parts[1] + "." + parts[2].substring(0, parts[2].length()-1) + alphabet.charAt(last + 1));
        invalid(sign(new byte[]{(byte)0xC3, 0x28}, BODY.getBytes(StandardCharsets.UTF_8), KEY));
        invalid(sign(HEADER.getBytes(StandardCharsets.UTF_8), new byte[]{(byte)0xC3, 0x28}, KEY));
        invalid(sign(HEADER + " ".repeat(1024), BODY)); invalid(sign(HEADER, BODY + " ".repeat(4096)));
        invalid("x".repeat(8193));
    }
    @Test void exactDecodedSegmentBoundariesAndOptionalNotBefore() {
        assertDoesNotThrow(() -> verifier(CLOCK).verify(sign(HEADER + " ".repeat(1024 - HEADER.length()), BODY)));
        invalid(sign(HEADER + " ".repeat(1025 - HEADER.length()), BODY));
        assertDoesNotThrow(() -> verifier(CLOCK).verify(sign(HEADER, BODY + " ".repeat(4096 - BODY.length()))));
        invalid(sign(HEADER, BODY + " ".repeat(4097 - BODY.length())));
        assertDoesNotThrow(() -> verifier(CLOCK).verify(sign(HEADER, BODY.replace("}", ",\"nbf\":1900000100}"))));
    }
    @Test void keySourceIsLocalExplicitAndFailureTyped() {
        String token = sign(HEADER.replace("}", ",\"kid\":\"key-1\"}"), BODY);
        JwtCryptographicVerifier selected = new JwtCryptographicVerifier(policy("ctx"), (kid, alg) -> {
            assertEquals(Optional.of("key-1"), kid); assertEquals("HS256", alg); return new SecretKeySpec(KEY,"HmacSHA256");
        }, CLOCK);
        assertDoesNotThrow(() -> selected.verify(token));
        assertEquals(SecurityValidationFailure.TOKEN_INVALID, assertThrows(SecurityValidationException.class,
                () -> new JwtCryptographicVerifier(policy("ctx"), (k,a) -> null, CLOCK).verify(token)).failure());
        assertEquals(SecurityValidationFailure.CONTRACT_VIOLATION, assertThrows(SecurityValidationException.class,
                () -> new JwtCryptographicVerifier(policy("ctx"), (k,a) -> new SecretKeySpec(new byte[16],"HmacSHA256"), CLOCK).verify(token)).failure());
        assertEquals(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE, assertThrows(SecurityValidationException.class,
                () -> new JwtCryptographicVerifier(policy("ctx"), (k,a) -> { throw new SecurityValidationException(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE); }, CLOCK).verify(token)).failure());
        SecurityValidationException broken = assertThrows(SecurityValidationException.class,
                () -> new JwtCryptographicVerifier(policy("ctx"), (k,a) -> { throw new IllegalArgumentException("external-secret"); }, CLOCK).verify(token));
        assertEquals(SecurityValidationFailure.CONTRACT_VIOLATION, broken.failure());
        assertFalse(broken.toString().contains("external-secret")); assertNull(broken.getCause());
    }
    @Test void invalidConfigurationAndExactTimePolicy() {
        assertThrows(IllegalArgumentException.class, () -> new JwtVerificationPolicy("ctx","issuer",Set.of("a"),Set.of("RS256"),Duration.ZERO,Duration.ofMinutes(1),StrictJwtJsonTest.LIMITS));
        for (Duration skew : List.of(Duration.ofNanos(-1), Duration.ofSeconds(61))) assertThrows(IllegalArgumentException.class,
                () -> new JwtVerificationPolicy("ctx","issuer",Set.of("a"),Set.of("HS256"),skew,Duration.ofMinutes(1),StrictJwtJsonTest.LIMITS));
        assertThrows(IllegalArgumentException.class, () -> new JwtReadLimits(8193,1024,4096,8,256,64,1024,20));
        assertThrows(IllegalArgumentException.class, () -> new JwtReadLimits(8192,1024,4096,0,256,64,1024,20));
        JwtVerificationPolicy skewed = new JwtVerificationPolicy("ctx","issuer-fixture",Set.of("resource-fixture"),Set.of("HS256"),Duration.ofSeconds(60),Duration.ofMinutes(15),StrictJwtJsonTest.LIMITS);
        JwtCryptographicVerifier verifier = new JwtCryptographicVerifier(skewed,(k,a)->new SecretKeySpec(KEY,"HmacSHA256"),CLOCK);
        assertDoesNotThrow(() -> verifier.verify(sign(HEADER,BODY.replace("1900000000","1900000160"))));
        assertThrows(SecurityValidationException.class, () -> verifier.verify(sign(HEADER,BODY.replace("1900000000","1900000161"))));
        assertThrows(SecurityValidationException.class, () -> verifier.verify(sign(HEADER,BODY.replace("1900000900","1900000100"))));
    }
}
