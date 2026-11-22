package com.davidrr.security.spring.account;

import org.springframework.security.authentication.AuthenticationServiceException;

/** Known inability to make an authoritative decision; never retains external diagnostics. */
public final class AuthoritativeAuthenticationServiceException extends AuthenticationServiceException {
    private static final long serialVersionUID = 1L;
    public AuthoritativeAuthenticationServiceException() { super("Security service unavailable"); }
}
