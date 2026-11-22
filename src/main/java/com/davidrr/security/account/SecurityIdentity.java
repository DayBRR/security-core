package com.davidrr.security.account;

import java.nio.charset.StandardCharsets;

/** Stable identity within a trusted authority; never a username lookup key. */
public record SecurityIdentity(String namespace, String subjectId) {
    public SecurityIdentity {
        if (namespace == null || !namespace.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException("Invalid identity namespace");
        }
        requireText(subjectId, 256);
        if (subjectId.getBytes(StandardCharsets.UTF_8).length > 1024) throw new IllegalArgumentException("Invalid subject size");
    }

    static void requireText(String value, int maxCodePoints) {
        if (value == null || value.isEmpty() || value.length() > maxCodePoints * 2
                || value.codePointCount(0, value.length()) > maxCodePoints) throw new IllegalArgumentException("Invalid security text");
        int first = value.codePointAt(0), last = value.codePointBefore(value.length());
        if (Character.isWhitespace(first) || Character.isSpaceChar(first)
                || Character.isWhitespace(last) || Character.isSpaceChar(last)) throw new IllegalArgumentException("Invalid security text");
        for (int i = 0; i < value.length();) {
            int cp = value.codePointAt(i);
            if (Character.isISOControl(cp) || (cp >= 0xD800 && cp <= 0xDFFF)) throw new IllegalArgumentException("Invalid security text");
            i += Character.charCount(cp);
        }
    }

    @Override public String toString() { return "SecurityIdentity[REDACTED]"; }
}
