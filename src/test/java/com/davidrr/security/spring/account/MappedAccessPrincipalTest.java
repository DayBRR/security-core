package com.davidrr.security.spring.account;

import com.davidrr.security.account.SecurityIdentity;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MappedAccessPrincipalTest {
    @Test void rejectsNullsAndRedactsConsumerPrincipal() {
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        var user=AccountAccessAuthenticationProviderTest.Fixture.user(f.state.get());
        assertThrows(NullPointerException.class, () -> new MappedAccessPrincipal(null,user));
        assertThrows(NullPointerException.class, () -> new MappedAccessPrincipal(f.identity,null));
        var mapped=new MappedAccessPrincipal(f.identity,user);
        assertSame(user,mapped.principal()); assertEquals(f.identity,mapped.identity());
        assertEquals("MappedAccessPrincipal[REDACTED]",mapped.toString());
        assertNotEquals(f.identity,new SecurityIdentity("other",f.identity.subjectId()));
    }
}
