package com.davidrr.security.jwt.authoritative;

/** Explicit access-v1 structural ceilings; zero and unlimited values are forbidden. */
public record JwtReadLimits(int maxCompactBytes, int maxHeaderBytes, int maxPayloadBytes,
                            int maxDepth, int maxJsonTokens, int maxNameChars,
                            int maxStringChars, int maxNumberChars) {
    public JwtReadLimits {
        if (maxCompactBytes < 1 || maxCompactBytes > 8192
                || maxHeaderBytes < 1 || maxHeaderBytes > 1024
                || maxPayloadBytes < 1 || maxPayloadBytes > 4096
                || maxDepth < 1 || maxDepth > 8 || maxJsonTokens < 1 || maxJsonTokens > 256
                || maxNameChars < 1 || maxNameChars > 64
                || maxStringChars < 1 || maxStringChars > 1024
                || maxNumberChars < 1 || maxNumberChars > 20
                || maxHeaderBytes > maxCompactBytes || maxPayloadBytes > maxCompactBytes) {
            throw new IllegalArgumentException("Invalid access-v1 read limits");
        }
    }
}
