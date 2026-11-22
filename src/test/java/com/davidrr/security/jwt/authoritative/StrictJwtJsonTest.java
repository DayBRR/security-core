package com.davidrr.security.jwt.authoritative;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class StrictJwtJsonTest {
    static final JwtReadLimits LIMITS = new JwtReadLimits(8192, 1024, 4096, 8, 256, 64, 1024, 20);
    private final StrictJwtJson reader = new StrictJwtJson(LIMITS);
    private Map<String, Object> read(String json) { return reader.read(json.getBytes(StandardCharsets.UTF_8), 4096); }

    @ParameterizedTest
    @ValueSource(strings = {"{\"a\":1,\"a\":1}", "{\"a\":1,\"\\u0061\":2}",
            "{\"o\":{\"x\":1,\"x\":2}}", "{\"a\":[{\"x\":0,\"x\":1}]}",
            "{}{}", "{} 1", "{", "{\"x\":}", "[]", "null", "\uFEFF{}", "{/*x*/}",
            "{'a':1}", "{a:1}", "{\"a\":NaN}", "{\"a\":01}", "{\"a\":1,}",
            "{\"x\":\"\\ud800\"}", "{\"\\udc00\":0}"})
    void rejectsAdversarialRawJson(String json) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> read(json));
        assertEquals("Invalid JWT JSON", error.getMessage()); assertNull(error.getCause());
    }

    @Test void rejectsInvalidUtf8AndEncodingAutoDetection() {
        assertThrows(IllegalArgumentException.class, () -> reader.read(new byte[]{'{','"','x','"',':','"',(byte)0xC3,0x28,'"','}'}, 4096));
        assertThrows(IllegalArgumentException.class, () -> reader.read("{}".getBytes(StandardCharsets.UTF_16BE), 4096));
    }

    @Test void exactDepthAndTokenCeilings() {
        assertDoesNotThrow(() -> read("{\"x\":".repeat(7) + "{}" + "}".repeat(7)));
        assertThrows(IllegalArgumentException.class, () -> read("{\"x\":".repeat(8) + "{}" + "}".repeat(8)));
        // Object start + name + array start + 251 scalars + array end + object end = 256.
        assertDoesNotThrow(() -> read("{\"x\":[" + String.join(",", Collections.nCopies(251, "0")) + "]}"));
        assertThrows(IllegalArgumentException.class, () -> read("{\"x\":[" + String.join(",", Collections.nCopies(252, "0")) + "]}"));
    }

    @Test void exactNameStringNumberAndByteCeilings() {
        assertDoesNotThrow(() -> read("{\"" + "a".repeat(64) + "\":0}"));
        assertThrows(IllegalArgumentException.class, () -> read("{\"" + "a".repeat(65) + "\":0}"));
        assertDoesNotThrow(() -> read("{\"x\":\"" + "a".repeat(1024) + "\"}"));
        assertThrows(IllegalArgumentException.class, () -> read("{\"x\":\"" + "a".repeat(1025) + "\"}"));
        assertDoesNotThrow(() -> read("{\"x\":" + "1".repeat(20) + "}"));
        assertThrows(IllegalArgumentException.class, () -> read("{\"x\":" + "1".repeat(21) + "}"));
        byte[] exact = ("{}" + " ".repeat(4094)).getBytes(StandardCharsets.UTF_8);
        assertDoesNotThrow(() -> reader.read(exact, 4096));
        assertThrows(IllegalArgumentException.class, () -> reader.read(Arrays.copyOf(exact, 4097), 4096));
    }

    @Test @SuppressWarnings("unchecked") void resultsAreDeeplyImmutable() {
        Map<String, Object> result = read("{\"x\":[{\"y\":null}]}");
        assertThrows(UnsupportedOperationException.class, () -> result.put("z", 0));
        List<Object> nested = (List<Object>) result.get("x");
        assertThrows(UnsupportedOperationException.class, () -> nested.add(0));
        assertThrows(UnsupportedOperationException.class, () -> ((Map<String,Object>) nested.get(0)).put("z", 0));
    }
}
