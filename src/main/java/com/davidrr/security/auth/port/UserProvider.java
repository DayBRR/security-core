package com.davidrr.security.auth.port;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserProvider {

    UserDetails loadUserByUsername(String username);
}