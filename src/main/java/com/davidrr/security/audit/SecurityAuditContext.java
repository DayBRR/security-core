package com.davidrr.security.audit;

public record SecurityAuditContext(
        String username,
        String ip,
        String userAgent,
        Long sessionId,
        String reason,
        String details
) {
    public static SecurityAuditContext of(
            String username,
            String ip,
            String userAgent,
            Long sessionId,
            String reason,
            String details
    ) {
        return new SecurityAuditContext(username, ip, userAgent, sessionId, reason, details);
    }

    public static SecurityAuditContext minimal(String username, String ip, String userAgent) {
        return new SecurityAuditContext(username, ip, userAgent, null, null, null);
    }
}