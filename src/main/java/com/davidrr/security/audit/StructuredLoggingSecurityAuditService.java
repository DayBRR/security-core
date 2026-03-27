package com.davidrr.security.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class StructuredLoggingSecurityAuditService implements SecurityAuditService {

    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("SECURITY_AUDIT");

    @Override
    public void log(SecurityEventType eventType, SecurityAuditContext context) {
        SECURITY_LOG.info(
                "type={} username={} ip={} userAgent=\"{}\" sessionId={} reason={} details=\"{}\"",
                eventType,
                safe(context.username()),
                safe(context.ip()),
                safe(context.userAgent()),
                context.sessionId(),
                safe(context.reason()),
                safe(context.details())
        );
    }

    private String safe(String value) {
        return value == null ? "-" : value;
    }
}