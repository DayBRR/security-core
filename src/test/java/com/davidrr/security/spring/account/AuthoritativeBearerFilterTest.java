package com.davidrr.security.spring.account;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class AuthoritativeBearerFilterTest {
    @AfterEach void clean() { SecurityContextHolder.clearContext(); }
    @ParameterizedTest @ValueSource(strings={"", "Bearer", "Bearer ", "Bearer  a", "Bearer\ta", "Basic a", "Bearer a,b", "Bearer a b", " Bearer a", "Bearer a\t", "Bearer \u00e9", "Bearer a\n"})
    void invalidHeaderTerminatesWithoutLookupOrProtectedEffects(String header) throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.addHeader("Authorization",header); var reply=new MockHttpServletResponse();
        f.filter().doFilter(request,reply,(r,s)->fail("Protected execution after rejection"));
        assertEquals(401,reply.getStatus()); assertEquals(0,f.reads.get()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void duplicateAndOversizeHeadersAreRejected() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        for(boolean duplicate:new boolean[]{true,false}) {
            var request=new MockHttpServletRequest(); request.addHeader("Authorization",duplicate?"Bearer "+f.token():"Bearer "+"a".repeat(8193));
            if(duplicate) request.addHeader("Authorization","Bearer "+f.token());
            var reply=new MockHttpServletResponse(); f.filter().doFilter(request,reply,(r,s)->fail()); assertEquals(401,reply.getStatus());
        }
        assertEquals(0,f.reads.get());
    }
    @Test void absentHeaderDoesNotUseCookieQueryFormOrResidualContext() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("SESSION",f.token())); request.addParameter("access_token",f.token());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("residual",null,java.util.List.of()));
        AtomicInteger calls=new AtomicInteger(); f.filter().doFilter(request,new MockHttpServletResponse(),(r,s)->{
            calls.incrementAndGet(); assertNull(SecurityContextHolder.getContext().getAuthentication());
        });
        assertEquals(1,calls.get()); assertEquals(0,f.reads.get()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void matcherGapInsideInvokedAuthoritativeChainFailsClosedAndClearsResidualContext() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.addHeader("Authorization","Bearer "+f.token());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("residual",null,java.util.List.of()));
        var reply=new MockHttpServletResponse(); AtomicInteger calls=new AtomicInteger();
        var filter=new AuthoritativeBearerFilter(f.provider(),f.writer(),r->false);
        filter.doFilter(request,reply,(r,s)->calls.incrementAndGet());
        assertEquals(503,reply.getStatus()); assertEquals(0,calls.get()); assertEquals(0,f.reads.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void matcherFailureIsSanitizedInternalErrorAndCannotReachGateOrChain() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.addHeader("Authorization","Bearer "+f.token());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("residual",null,java.util.List.of()));
        var reply=new MockHttpServletResponse(); AtomicInteger calls=new AtomicInteger();
        var filter=new AuthoritativeBearerFilter(f.provider(),f.writer(),r->{throw new IllegalStateException("matcher-private-sentinel");});
        filter.doFilter(request,reply,(r,s)->calls.incrementAndGet());
        assertEquals(500,reply.getStatus()); assertTrue(reply.getContentAsString().contains("SECURITY_INTERNAL_ERROR"));
        assertFalse(reply.getContentAsString().contains("matcher-private-sentinel"));
        assertEquals(0,f.reads.get()); assertEquals(0,calls.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void existingAuthenticationCannotSkipGateAndBusinessExceptionIsNotReclassified() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.addHeader("Authorization","bEaReR "+f.token()); var reply=new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("residual",null,java.util.List.of()));
        var business=new IllegalStateException("business");
        assertSame(business,assertThrows(IllegalStateException.class, () -> f.filter().doFilter(request,reply,(r,s)->{
            assertEquals("current-name",SecurityContextHolder.getContext().getAuthentication().getName()); throw business;
        })));
        assertEquals(1,f.reads.get()); assertEquals(200,reply.getStatus()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void knownAndUnexpectedFaultsAreTerminal503And500() throws Exception {
        for(boolean known:new boolean[]{true,false}) {
            var f=new AccountAccessAuthenticationProviderTest.Fixture();
            f.failure.set(known?new com.davidrr.security.account.SecurityValidationException(com.davidrr.security.account.SecurityValidationFailure.DEPENDENCY_UNAVAILABLE)
                    :new IllegalStateException("external-secret"));
            var request=new MockHttpServletRequest(); request.addHeader("Authorization","Bearer "+f.token());
            var reply=new MockHttpServletResponse(); f.filter().doFilter(request,reply,(r,s)->fail());
            assertEquals(known?503:500,reply.getStatus()); assertFalse(reply.getContentAsString().contains("secret"));
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }
}
