package com.davidrr.security.spring.account;

import com.davidrr.security.account.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import java.util.*;
import java.util.concurrent.Callable;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthoritativeBearerMockMvcTest {
    @Configuration(proxyBeanMethods=false) @EnableWebSecurity @EnableWebMvc @EnableMethodSecurity
    static class Config {
        @Bean AccountAccessAuthenticationProviderTest.Fixture fixture(){return new AccountAccessAuthenticationProviderTest.Fixture();}
        @Bean AccountAuthenticationFailureHandler failures(AccountAccessAuthenticationProviderTest.Fixture f){return f.writer();}
        @Bean AccountAccessAuthenticationProvider provider(AccountAccessAuthenticationProviderTest.Fixture f){return f.provider();}
        @Bean SecurityFilterChain channel(HttpSecurity http, AccountAccessAuthenticationProvider provider, AccountAuthenticationFailureHandler failures) throws Exception {
            var filter=new AuthoritativeBearerFilter(provider,failures,r->!target(r).equals("/misconfigured"));
            http.securityContext(c->c.securityContextRepository(new NullSecurityContextRepository()))
                    .sessionManagement(c->c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .requestCache(c->c.requestCache(new NullRequestCache()))
                    .exceptionHandling(c->c.authenticationEntryPoint(failures).accessDeniedHandler(failures))
                    .csrf(c->c.disable()) // Synthetic Bearer-only fixture, no ambient credential acceptor.
                    .authorizeHttpRequests(c->c.requestMatchers(r->Set.of("/public","/forward","/include","/async").contains(target(r))).permitAll()
                            .requestMatchers(r->target(r).equals("/write")).hasAuthority("scope:write")
                            .anyRequest().hasAuthority("scope:read"))
                    .addFilterBefore(filter,AnonymousAuthenticationFilter.class);
            SecurityFilterChain chain=http.build();
            AuthoritativeBearerComposition.validate(chain,List.of());
            return chain;
        }
        static String target(HttpServletRequest r){
            Object included=r.getAttribute(RequestDispatcher.INCLUDE_REQUEST_URI);
            return r.getDispatcherType()==DispatcherType.INCLUDE && included instanceof String s?s:r.getRequestURI();
        }
        @Bean SmartInitializingSingleton validateRegistrations(SecurityFilterChain chain,org.springframework.context.ApplicationContext context){
            return ()->{
                List<Filter> standalone=new ArrayList<>();
                for(FilterRegistrationBean<?> bean:context.getBeansOfType(FilterRegistrationBean.class).values()) {
                    if(bean.isEnabled()) standalone.add(bean.getFilter());
                }
                AuthoritativeBearerComposition.validate(chain,standalone);
            };
        }
        @Bean Endpoints endpoints(AccountAccessAuthenticationProviderTest.Fixture f){return new Endpoints(f);}
    }
    @RestController
    static class Endpoints {
        final AccountAccessAuthenticationProviderTest.Fixture f;
        Endpoints(AccountAccessAuthenticationProviderTest.Fixture f){this.f=f;}
        @GetMapping("/public") String publicRoute(){return "public";}
        @GetMapping({"/read","/write","/misconfigured"}) String resource(){f.effects.incrementAndGet();return SecurityContextHolder.getContext().getAuthentication().getName();}
        @GetMapping("/method") @org.springframework.security.access.prepost.PreAuthorize("hasAuthority('scope:write')")
        String method(){f.effects.incrementAndGet();return "method";}
        @GetMapping("/forward") void forward(HttpServletRequest r,HttpServletResponse s) throws Exception {r.getRequestDispatcher("/read").forward(r,s);}
        @GetMapping("/include") void include(HttpServletRequest r,HttpServletResponse s) throws Exception {r.getRequestDispatcher("/read").include(r,s);}
        @GetMapping("/async") Callable<String> async(){return ()->SecurityContextHolder.getContext().getAuthentication()==null?"anonymous-worker":SecurityContextHolder.getContext().getAuthentication().getName();}
    }
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private AccountAccessAuthenticationProviderTest.Fixture f;
    @BeforeEach void start(){
        context=new AnnotationConfigWebApplicationContext();context.setServletContext(new org.springframework.mock.web.MockServletContext());
        context.register(Config.class);context.refresh();f=context.getBean(AccountAccessAuthenticationProviderTest.Fixture.class);
        mvc=MockMvcBuilders.webAppContextSetup(context).addFilters(context.getBean("springSecurityFilterChain",Filter.class)).build();
    }
    @AfterEach void close(){if(context!=null)context.close();SecurityContextHolder.clearContext();}
    @Test void publicAndProtectedAbsenceAreDistinctAndSessionCannotAuthenticate() throws Exception {
        mvc.perform(get("/public")).andExpect(status().isOk());
        mvc.perform(get("/read")).andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate","Bearer"));
        var session=new org.springframework.mock.web.MockHttpSession();
        session.setAttribute("SPRING_SECURITY_CONTEXT",SecurityContextHolder.createEmptyContext());
        mvc.perform(get("/read").session(session)).andExpect(status().isUnauthorized());
        assertEquals(0,f.reads.get());assertEquals(0,f.effects.get());
    }
    @Test void realBearerReachesControllerAndInsufficientAuthorityIs403() throws Exception {
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token())).andExpect(status().isOk()).andExpect(content().string("current-name"));
        mvc.perform(get("/write").header("Authorization","Bearer "+f.token())).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("AUTH_FORBIDDEN"));
        mvc.perform(get("/method").header("Authorization","Bearer "+f.token())).andExpect(status().isForbidden());
        assertEquals(3,f.reads.get());assertEquals(1,f.effects.get());assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void publicInvalidAndDuplicateBearerAreTerminalAndCookieIsIgnored() throws Exception {
        mvc.perform(get("/public").header("Authorization","Bearer legacy")).andExpect(status().isUnauthorized());
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token(),"Bearer "+f.token())).andExpect(status().isUnauthorized());
        mvc.perform(get("/read").cookie(new Cookie("SESSION",f.token())).param("access_token",f.token())).andExpect(status().isUnauthorized());
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token()).cookie(new Cookie("SESSION","ignored"))).andExpect(status().isOk());
        assertEquals(1,f.reads.get());assertEquals(1,f.effects.get());
    }
    @Test void matcherGapInSelectedAuthoritativeChainIsTerminalAndCannotFallback() throws Exception {
        mvc.perform(get("/misconfigured").header("Authorization","Bearer "+f.token()))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("SECURITY_DEPENDENCY_UNAVAILABLE"));
        assertEquals(0,f.reads.get()); assertEquals(0,f.effects.get());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void stateAndKnownTechnicalFailuresDifferWithoutInternalDetails() throws Exception {
        for(int scenario=0;scenario<5;scenario++) {
            f.state.set(AccountAccessAuthenticationProviderTest.Fixture.snapshot(f.identity,"7",AdmissionState.ADMITTED));f.failure.set(null);
            switch(scenario){
                case 0->f.state.set(null);
                case 1->f.state.set(AccountAccessAuthenticationProviderTest.Fixture.snapshot(f.identity,"8",AdmissionState.ADMITTED));
                case 2->f.state.set(AccountAccessAuthenticationProviderTest.Fixture.snapshot(f.identity,"7",AdmissionState.NOT_ADMITTED));
                case 3->f.failure.set(new SecurityValidationException(SecurityValidationFailure.DEPENDENCY_UNAVAILABLE));
                default->f.failure.set(new IllegalStateException("private-sentinel"));
            }
            int expected=scenario<3?401:scenario==3?503:500;
            var result=mvc.perform(get("/read").header("Authorization","Bearer "+f.token())).andExpect(status().is(expected)).andReturn();
            assertFalse(result.getResponse().getContentAsString().contains("private-sentinel"));
        }
        assertEquals(0,f.effects.get());
    }
    @Test void cryptoRejectsBeforeAccountAndNextRequestSeesDisable() throws Exception {
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token("external:alpha","7",1900000900,new byte[32]))).andExpect(status().isUnauthorized());
        assertEquals(0,f.reads.get());
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token())).andExpect(status().isOk());
        f.state.set(AccountAccessAuthenticationProviderTest.Fixture.snapshot(f.identity,"8",AdmissionState.NOT_ADMITTED));
        mvc.perform(get("/read").header("Authorization","Bearer "+f.token())).andExpect(status().isUnauthorized());
        assertEquals(1,f.effects.get());
    }
    @Test void mvcCallablePropagatesIdentityAndAsyncRedispatchRevalidates() throws Exception {
        MvcResult pending=mvc.perform(get("/async").header("Authorization","Bearer "+f.token())).andExpect(request().asyncStarted()).andReturn();
        assertEquals("current-name",pending.getAsyncResult(5000));
        mvc.perform(asyncDispatch(pending)).andExpect(status().isOk()).andExpect(content().string("current-name"));
        assertEquals(2,f.reads.get());assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
