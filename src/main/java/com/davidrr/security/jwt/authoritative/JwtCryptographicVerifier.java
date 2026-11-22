package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.DeserializationException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.*;
import java.util.*;
import static com.davidrr.security.account.SecurityValidationFailure.*;

/** Explicit access-v1 verification; not a Spring bean, filter, issuer or legacy adapter. */
public final class JwtCryptographicVerifier {
    private static final Set<String> HEADER = Set.of("alg", "typ", "kid");
    private static final Set<String> REQUIRED = Set.of("iss", "aud", "sub", "identity_namespace", "security_revision_scheme",
            "security_revision", "token_use", "iat", "exp", "jti");
    private final JwtVerificationPolicy policy;
    private final TrustedJwtKeySource keys;
    private final java.time.Clock clock;
    private final StrictJwtJson json;

    public JwtCryptographicVerifier(JwtVerificationPolicy policy, TrustedJwtKeySource keys, java.time.Clock clock) {
        this.policy = Objects.requireNonNull(policy); this.keys = Objects.requireNonNull(keys);
        this.clock = Objects.requireNonNull(clock); this.json = new StrictJwtJson(policy.readLimits());
    }
    public String securityContextId() { return policy.securityContextId(); }

    public VerifiedJwtClaims verify(String compactToken) {
        try {
            JwtReadLimits limits = policy.readLimits();
            if (compactToken == null || compactToken.isEmpty() || compactToken.length() > limits.maxCompactBytes()) throw invalid();
            for (int i = 0; i < compactToken.length(); i++) {
                char c = compactToken.charAt(i);
                if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.')) throw invalid();
            }
            String[] segments = compactToken.split("\\.", -1);
            if (segments.length != 3) throw invalid();
            byte[] headerBytes = decode(segments[0], limits.maxHeaderBytes());
            byte[] payloadBytes = decode(segments[1], limits.maxPayloadBytes());
            if (decode(segments[2], 32).length != 32) throw invalid();
            Map<String, Object> header = json.read(headerBytes, limits.maxHeaderBytes());
            Map<String, Object> payload = json.read(payloadBytes, limits.maxPayloadBytes());
            if (!HEADER.containsAll(header.keySet()) || !"HS256".equals(header.get("alg")) || !"at+jwt".equals(header.get("typ"))) throw invalid();
            Optional<String> kid = Optional.empty();
            if (header.containsKey("kid")) {
                String value = string(header.get("kid"));
                if (!value.matches("[A-Za-z0-9._:-]{1,128}")) throw invalid();
                kid = Optional.of(value);
            }
            Key key = verificationKey(kid);
            long skewSeconds = policy.clockSkew().getSeconds() + (policy.clockSkew().getNano() == 0 ? 0 : 1);
            JwtParser parser = Jwts.parserBuilder().setSigningKey(key)
                    .setClock(() -> Date.from(clock.instant())).setAllowedClockSkewSeconds(skewSeconds)
                    .deserializeJsonWith(bytes -> {
                        try { return json.read(bytes, Math.max(limits.maxHeaderBytes(), limits.maxPayloadBytes())); }
                        catch (IllegalArgumentException failure) { throw new DeserializationException("Invalid JWT JSON"); }
                    }).build();
            // parse() verifies the original signing input, including JSON whitespace. Own strict
            // preflight covers payloads JJWT treats as plaintext rather than Claims.
            if (!(parser.parse(compactToken) instanceof Jws<?>)) throw invalid();
            validateClaims(payload);
            return new VerifiedJwtClaims(payload, securityContextId());
        } catch (JwtException | IllegalArgumentException failure) { throw invalid(); }
    }

    private Key verificationKey(Optional<String> kid) {
        try {
            Key key = keys.verificationKey(kid, "HS256");
            if (key == null) throw invalid(); // Unknown key; unavailable sources use a typed failure.
            if (!(key instanceof SecretKey) || !"HmacSHA256".equalsIgnoreCase(key.getAlgorithm())) {
                throw new SecurityValidationException(CONTRACT_VIOLATION);
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length < 32) throw new SecurityValidationException(CONTRACT_VIOLATION);
            return new SecretKeySpec(encoded, "HmacSHA256");
        } catch (SecurityValidationException failure) { throw failure; }
        catch (RuntimeException failure) {
            // A broken key adapter is not an invalid caller credential; redact its diagnostics.
            throw new SecurityValidationException(CONTRACT_VIOLATION);
        }
    }

    private void validateClaims(Map<String, Object> values) {
        if (!values.keySet().containsAll(REQUIRED) || values.keySet().stream().anyMatch(k -> !REQUIRED.contains(k) && !k.equals("nbf"))) throw invalid();
        if (!policy.issuer().equals(values.get("iss")) || !(values.get("aud") instanceof String audience)
                || !policy.audiences().contains(audience) || !"access".equals(values.get("token_use"))) throw invalid();
        for (String name : List.of("sub", "identity_namespace", "security_revision_scheme", "security_revision")) string(values.get(name));
        if (!string(values.get("jti")).matches("[A-Za-z0-9._:-]{1,128}")) throw invalid();
        Instant iat = date(values.get("iat")), exp = date(values.get("exp")), now = clock.instant();
        if (!exp.isAfter(iat) || Duration.between(iat, exp).compareTo(policy.maxTokenLifetime()) > 0
                || iat.isAfter(now.plus(policy.clockSkew())) || !exp.isAfter(now)) throw invalid();
        if (values.containsKey("nbf")) {
            Instant nbf = date(values.get("nbf"));
            if (!nbf.isBefore(exp) || nbf.isAfter(now.plus(policy.clockSkew()))) throw invalid();
        }
    }

    private static Instant date(Object value) {
        if (!(value instanceof Long seconds) || seconds < 0 || seconds > 253402300799L) throw invalid();
        return Instant.ofEpochSecond(seconds);
    }
    private static String string(Object value) {
        if (!(value instanceof String text) || text.isEmpty()) throw invalid();
        return text;
    }
    private static byte[] decode(String segment, int maxBytes) {
        if (segment.isEmpty() || segment.length() > ((long) maxBytes * 4 + 2) / 3) throw invalid();
        byte[] bytes = Base64.getUrlDecoder().decode(segment);
        if (bytes.length > maxBytes || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(segment)) throw invalid();
        return bytes;
    }
    private static SecurityValidationException invalid() { return new SecurityValidationException(TOKEN_INVALID); }
}
