package com.davidrr.security.auth.port;

public interface UserRegistrationPort {

    RegisteredUser register(String username, String email, String encodedPassword);

    record RegisteredUser(Long id, String username) {}
}