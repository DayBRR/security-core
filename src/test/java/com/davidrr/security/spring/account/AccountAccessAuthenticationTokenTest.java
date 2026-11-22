package com.davidrr.security.spring.account;

import org.junit.jupiter.api.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class AccountAccessAuthenticationTokenTest {
    @Test void inputCannotElevateAndNeitherJavaNorJsonSerializationExposesJwt() throws Exception {
        String secret="synthetic-private-jwt-sentinel";
        var input=new AccountAccessAuthenticationToken(secret);
        assertFalse(input.isAuthenticated()); assertNull(input.getPrincipal()); assertNull(input.getCredentials());
        assertNull(input.getDetails()); assertTrue(input.getAuthorities().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> input.setAuthenticated(true));
        assertFalse(input.toString().contains(secret));
        assertFalse(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(input).contains(secret));
        var bytes=new ByteArrayOutputStream();
        try(var out=new ObjectOutputStream(bytes)) { out.writeObject(input); }
        assertFalse(bytes.toString(StandardCharsets.ISO_8859_1).contains(secret));
        try(var in=new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            assertNull(((AccountAccessAuthenticationToken)in.readObject()).compactToken());
        }
        input.eraseCredentials(); input.eraseCredentials(); assertNull(input.compactToken());
    }
    @Test void successIsSeparateImmutablePermissionResultWithNoCompact() {
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        var input=new AccountAccessAuthenticationToken(f.token());
        var result=(AccountAccessAuthenticationToken)f.provider().authenticate(input);
        assertNotSame(input,result); assertNull(result.compactToken()); assertNull(input.compactToken());
        assertNull(result.getCredentials()); assertNull(result.getDetails());
        assertThrows(UnsupportedOperationException.class, () -> result.getAuthorities().clear());
        result.setAuthenticated(false); assertFalse(result.isAuthenticated());
        assertThrows(IllegalArgumentException.class, () -> result.setAuthenticated(true));
        assertEquals(1,AccountAccessAuthenticationToken.class.getConstructors().length);
    }
}
