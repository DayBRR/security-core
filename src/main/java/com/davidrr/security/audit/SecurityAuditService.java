package com.davidrr.security.audit;

public interface SecurityAuditService {

    void log(SecurityEventType eventType, SecurityAuditContext context);
}
