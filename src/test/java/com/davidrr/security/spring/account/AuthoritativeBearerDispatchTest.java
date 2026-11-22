package com.davidrr.security.spring.account;

import com.davidrr.security.account.*;
import jakarta.servlet.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthoritativeBearerDispatchTest {
    @AfterEach void clean(){SecurityContextHolder.clearContext();}
    @ParameterizedTest @EnumSource(value=DispatcherType.class,names={"REQUEST","ASYNC","FORWARD","INCLUDE"})
    void everyAcceptanceRevalidatesAndCleansItsContext(DispatcherType type) throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var request=new MockHttpServletRequest();
        request.setDispatcherType(type); request.addHeader("Authorization","Bearer "+f.token());
        f.filter().doFilter(request,new MockHttpServletResponse(),(r,s)->assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()));
        assertEquals(1,f.reads.get()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @ParameterizedTest @EnumSource(value=DispatcherType.class,names={"FORWARD","INCLUDE"})
    void nestedDispatchRestoresOnlyItsOwnOuterContextAndRevalidates(DispatcherType type) throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var filter=f.filter(); var outer=new MockHttpServletRequest();
        outer.addHeader("Authorization","Bearer "+f.token());
        filter.doFilter(outer,new MockHttpServletResponse(),(r,s)->{
            SecurityContext original=SecurityContextHolder.getContext();
            var nested=new MockHttpServletRequest(); nested.setDispatcherType(type); nested.addHeader("Authorization","Bearer "+f.token());
            filter.doFilter(nested,new MockHttpServletResponse(),(nr,ns)->assertNotSame(original,SecurityContextHolder.getContext()));
            assertSame(original,SecurityContextHolder.getContext());
        });
        assertEquals(2,f.reads.get()); assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void includeRejectsWithoutExecutingAndErrorNeverReauthenticatesOrWritesTwice() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var include=new MockHttpServletRequest();
        include.setDispatcherType(DispatcherType.INCLUDE); include.addHeader("Authorization","Bearer invalid");
        assertThrows(ServletException.class,()->f.filter().doFilter(include,new MockHttpServletResponse(),(r,s)->fail()));
        var error=new MockHttpServletRequest(); error.setDispatcherType(DispatcherType.ERROR); error.addHeader("Authorization","Bearer "+f.token());
        var reply=new MockHttpServletResponse(); f.filter().doFilter(error,reply,(r,s)->fail()); assertEquals(500,reply.getStatus());
        String body=reply.getContentAsString(); reply.flushBuffer(); f.filter().doFilter(error,reply,(r,s)->fail());
        assertEquals(body,reply.getContentAsString()); assertEquals(0,f.reads.get());
    }
    @Test void asyncRedispatchAfterCommittedDisableRejectsInsteadOfUsingEarlierAcceptance() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var filter=f.filter();
        var request=new MockHttpServletRequest(); request.addHeader("Authorization","Bearer "+f.token());
        filter.doFilter(request,new MockHttpServletResponse(),(r,s)->assertNotNull(SecurityContextHolder.getContext().getAuthentication()));
        f.state.set(AccountAccessAuthenticationProviderTest.Fixture.snapshot(f.identity,"8",AdmissionState.NOT_ADMITTED));
        request.setDispatcherType(DispatcherType.ASYNC); var reply=new MockHttpServletResponse();
        filter.doFilter(request,reply,(r,s)->fail()); assertEquals(401,reply.getStatus()); assertEquals(2,f.reads.get());
    }
    @Test void concurrentWorkersAndExplicitPropagationUseSeparateContextsAndCleanReusedThread() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var filter=f.filter();
        ExecutorService pool=Executors.newFixedThreadPool(2); var barrier=new CyclicBarrier(2);
        try {
            Callable<SecurityContext> task=()->{
                var request=new MockHttpServletRequest(); request.addHeader("Authorization","Bearer "+f.token());
                var seen=new java.util.concurrent.atomic.AtomicReference<SecurityContext>();
                filter.doFilter(request,new MockHttpServletResponse(),(r,s)->{
                    seen.set(SecurityContextHolder.getContext());
                    try {barrier.await(5,TimeUnit.SECONDS);}catch(Exception e){throw new ServletException(e);}
                });
                assertNull(SecurityContextHolder.getContext().getAuthentication()); return seen.get();
            };
            Future<SecurityContext> a=pool.submit(task), b=pool.submit(task);
            var ca=a.get(10,TimeUnit.SECONDS); var cb=b.get(10,TimeUnit.SECONDS); assertNotSame(ca,cb);
            SecurityContext copied=SecurityContextHolder.createEmptyContext(); copied.setAuthentication(ca.getAuthentication());
            pool.submit(new org.springframework.security.concurrent.DelegatingSecurityContextRunnable(
                    ()->assertEquals("current-name",SecurityContextHolder.getContext().getAuthentication().getName()),copied)).get(5,TimeUnit.SECONDS);
            assertNull(pool.submit(()->SecurityContextHolder.getContext().getAuthentication()).get(5,TimeUnit.SECONDS));
        } finally {pool.shutdownNow();}
    }
}
