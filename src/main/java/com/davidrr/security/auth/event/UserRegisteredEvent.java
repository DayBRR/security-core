package com.davidrr.security.auth.event;

public record UserRegisteredEvent(Long userId, String username) { }