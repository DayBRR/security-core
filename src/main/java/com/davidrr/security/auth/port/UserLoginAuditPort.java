package com.davidrr.security.auth.port;

public interface UserLoginAuditPort {
    void recordSuccessfulLogin(String username);
}
