package com.davidrr.security.jwt.authoritative;

import com.davidrr.security.account.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class StrictIdentityClaimsCodecTest {
    private final StrictIdentityClaimsCodec codec = new StrictIdentityClaimsCodec("ctx", Set.of("counter-v1", "generation-v1"));
    private VerifiedJwtClaims claims(String field, Object value) {
        Map<String,Object> map = new HashMap<>(Map.of("sub","opaque:alpha","identity_namespace","fixture",
                "security_revision_scheme","counter-v1","security_revision","7"));
        if (value == null) map.remove(field); else map.put(field,value);
        return new VerifiedJwtClaims(map,"ctx");
    }
    static Stream<String> invalidCounters() { return Stream.of("", "-1", "+1", "01", "1.0", "1e0", " 1", "1 ", "9223372036854775808", "1".repeat(20)); }
    @ParameterizedTest @MethodSource("invalidCounters") void rejectsNonCanonicalCounters(String revision) {
        invalid(claims("security_revision",revision));
    }
    @ParameterizedTest @ValueSource(strings = {"sub","identity_namespace","security_revision_scheme","security_revision"})
    void missingOrWrongTypeNeverDefaults(String field) { invalid(claims(field,null)); invalid(claims(field,7L)); }
    private void invalid(VerifiedJwtClaims claims) {
        assertEquals(SecurityValidationFailure.TOKEN_INVALID, assertThrows(SecurityValidationException.class, () -> codec.decode(claims)).failure());
    }
    @Test void canonicalCountersStringsUuidsAndGeneration() {
        for (String revision : List.of("0","7","9223372036854775807")) assertEquals(revision,codec.decode(claims("security_revision",revision)).revision().value());
        for (String subject : List.of("opaque:alpha", UUID.fromString("a4d63919-4754-4b57-b668-3017a00dd1ae").toString())) {
            assertEquals(subject,codec.decode(claims("sub",subject)).identity().subjectId());
        }
        String generation = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        Map<String,Object> values = new HashMap<>(claims("security_revision",generation).claims());
        values.put("security_revision_scheme","generation-v1");
        assertEquals(generation,codec.decode(new VerifiedJwtClaims(values,"ctx")).revision().value());
        values.put("security_revision",generation + "="); invalid(new VerifiedJwtClaims(values,"ctx"));
        values.put("security_revision",generation.substring(0,42) + "B"); invalid(new VerifiedJwtClaims(values,"ctx"));
        values.put("security_revision","a".repeat(42)); invalid(new VerifiedJwtClaims(values,"ctx"));
    }
    @Test void rejectsUnknownDisabledSchemesAndWrongContext() {
        invalid(claims("security_revision_scheme","unknown"));
        StrictIdentityClaimsCodec restricted = new StrictIdentityClaimsCodec("ctx",Set.of("generation-v1"));
        assertThrows(SecurityValidationException.class, () -> restricted.decode(claims("sub","opaque")));
        assertEquals(SecurityValidationFailure.CONTRACT_VIOLATION, assertThrows(SecurityValidationException.class,
                () -> codec.decode(new VerifiedJwtClaims(claims("sub","opaque").claims(),"foreign"))).failure());
        assertThrows(IllegalArgumentException.class, () -> new StrictIdentityClaimsCodec("ctx",Set.of("unknown")));
        assertThrows(IllegalArgumentException.class, () -> new StrictIdentityClaimsCodec("ctx",Set.of()));
        assertThrows(SecurityValidationException.class, () -> codec.decode(null));
    }
}
