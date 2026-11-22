package com.davidrr.security.jwt.authoritative;

import com.fasterxml.jackson.core.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;

/** Private, bounded JSON reader shared by preflight and JJWT's deserialization hook. */
final class StrictJwtJson {
    private final JwtReadLimits limits;
    private final JsonFactory factory;

    StrictJwtJson(JwtReadLimits limits) {
        this.limits = Objects.requireNonNull(limits);
        factory = JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(limits.maxDepth()).maxTokenCount(limits.maxJsonTokens())
                        .maxNameLength(limits.maxNameChars()).maxStringLength(limits.maxStringChars())
                        .maxNumberLength(limits.maxNumberChars()).build()).build();
    }

    Map<String, Object> read(byte[] bytes, int byteLimit) {
        if (bytes == null || bytes.length == 0 || bytes.length > byteLimit) throw invalid();
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            if (text.charAt(0) == '\uFEFF') throw invalid();
            // A Reader prevents Jackson's UTF-16/32 auto-detection from reinterpreting valid UTF-8 NULs.
            try (JsonParser parser = factory.createParser(text)) {
                Cursor cursor = new Cursor(parser);
                if (cursor.next() != JsonToken.START_OBJECT) throw invalid();
                Map<String, Object> result = object(cursor, 1);
                if (cursor.next() != null) throw invalid();
                return result;
            }
        } catch (IOException | RuntimeException failure) {
            // Do not retain Jackson locations, input snippets, or external messages/causes.
            throw invalid();
        }
    }

    private Map<String, Object> object(Cursor cursor, int depth) throws IOException {
        if (depth > limits.maxDepth()) throw invalid();
        Map<String, Object> values = new LinkedHashMap<>();
        JsonToken token;
        while ((token = cursor.next()) != JsonToken.END_OBJECT) {
            if (token != JsonToken.FIELD_NAME) throw invalid();
            String name = cursor.parser.currentName();
            validateText(name, limits.maxNameChars());
            cursor.next();
            if (Set.of("iat", "exp", "nbf").contains(name)
                    && cursor.parser.currentToken() != null && cursor.parser.currentToken().isNumeric()
                    && !cursor.parser.getText().matches("0|[1-9][0-9]*")) throw invalid();
            values.put(name, value(cursor, depth));
        }
        return Collections.unmodifiableMap(values);
    }

    private Object value(Cursor cursor, int depth) throws IOException {
        JsonToken token = cursor.parser.currentToken();
        if (token == null) throw invalid();
        return switch (token) {
            case START_OBJECT -> object(cursor, depth + 1);
            case START_ARRAY -> {
                if (depth + 1 > limits.maxDepth()) throw invalid();
                List<Object> values = new ArrayList<>();
                while (cursor.next() != JsonToken.END_ARRAY) values.add(value(cursor, depth + 1));
                yield Collections.unmodifiableList(values);
            }
            case VALUE_STRING -> {
                String text = cursor.parser.getText();
                validateText(text, limits.maxStringChars());
                yield text;
            }
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> {
                if (cursor.parser.getTextLength() > limits.maxNumberChars()) throw invalid();
                // Preserve lexical integer/decimal distinction; never silently round a NumericDate.
                if (token == JsonToken.VALUE_NUMBER_INT) {
                    java.math.BigInteger number = cursor.parser.getBigIntegerValue();
                    yield number.bitLength() <= 63 ? (Object) number.longValueExact() : number;
                }
                yield cursor.parser.getDecimalValue();
            }
            case VALUE_TRUE -> Boolean.TRUE;
            case VALUE_FALSE -> Boolean.FALSE;
            case VALUE_NULL -> null;
            default -> throw invalid();
        };
    }

    private static void validateText(String text, int max) {
        if (text.length() > max) throw invalid();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (Character.isHighSurrogate(ch)) {
                if (++i >= text.length() || !Character.isLowSurrogate(text.charAt(i))) throw invalid();
            } else if (Character.isLowSurrogate(ch)) throw invalid();
        }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid JWT JSON"); }

    private final class Cursor {
        private final JsonParser parser;
        private int tokens;
        private Cursor(JsonParser parser) { this.parser = parser; }
        private JsonToken next() throws IOException {
            JsonToken token = parser.nextToken();
            if (token != null && ++tokens > limits.maxJsonTokens()) throw invalid();
            return token;
        }
    }
}
