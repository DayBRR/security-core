package com.davidrr.security.auth.port;

public interface UserRegistrationPort {

    RegisteredUser register(String username, String encodedPassword);

    record RegisteredUser(Long id, String username) {}
}