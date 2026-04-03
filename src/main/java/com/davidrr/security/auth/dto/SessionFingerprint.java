package com.davidrr.security.auth.dto;

import jakarta.servlet.http.HttpServletRequest;

public record SessionFingerprint(String ip, String userAgent) {
    public static SessionFingerprint from(HttpServletRequest request) {
        return new SessionFingerprint(
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
    }
}
