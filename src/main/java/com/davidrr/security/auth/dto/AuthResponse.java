package com.davidrr.security.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private final String token;

    @Override
    public String toString() {
        return "AuthResponse[REDACTED]";
    }
}
