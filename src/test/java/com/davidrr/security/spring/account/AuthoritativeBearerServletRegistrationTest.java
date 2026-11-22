package com.davidrr.security.spring.account;

import jakarta.servlet.*;
import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.*;
import org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.*;
import org.springframework.web.filter.DelegatingFilterProxy;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real embedded container and HTTP, including container-managed redispatches and registrations. */
class AuthoritativeBearerServletRegistrationTest {
    @Configuration(proxyBeanMethods=false)
    @Import({AuthoritativeBearerMockMvcTest.Config.class,DispatcherServletAutoConfiguration.class})
    static class Server {
        @Bean ServletWebServerFactory serverFactory(){
            var factory=new TomcatServletWebServerFactory(0);
            // The consumer must explicitly route container ERROR dispatches through its safe chain.
            factory.addErrorPages(new org.springframework.boot.web.server.ErrorPage("/error"));
            return factory;
        }
        @Bean DelegatingFilterProxyRegistrationBean securityRegistration(){
            var registration=new DelegatingFilterProxyRegistrationBean("springSecurityFilterChain");
            registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));registration.setAsyncSupported(true);
            return registration;
        }
    }
    @Configuration(proxyBeanMethods=false)
    static class Duplicate {
        @Bean FilterRegistrationBean<AuthoritativeBearerFilter> duplicate(AccountAccessAuthenticationProviderTest.Fixture f){
            return new FilterRegistrationBean<>(f.filter());
        }
    }
    static AnnotationConfigServletWebServerApplicationContext server(Class<?>... configs){
        var context=new AnnotationConfigServletWebServerApplicationContext();context.register(configs);
        try{context.refresh();return context;}catch(RuntimeException error){context.close();throw error;}
    }
    static HttpResponse<String> get(AnnotationConfigServletWebServerApplicationContext context,String path,String token) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+context.getWebServer().getPort()+path)).timeout(Duration.ofSeconds(10));
        if(token!=null)request.header("Authorization","Bearer "+token);
        return HttpClient.newHttpClient().send(request.GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    @Test void actualContainerHasOnlyProxyRegistrationAndExactlyOneBearerInChain() throws Exception {
        try(var context=server(Server.class)){
            var registrations=context.getServletContext().getFilterRegistrations();
            assertEquals(1,registrations.size());
            assertTrue(DelegatingFilterProxy.class.isAssignableFrom(Class.forName(registrations.values().iterator().next().getClassName())));
            var chain=context.getBean(org.springframework.security.web.SecurityFilterChain.class);
            assertEquals(1,chain.getFilters().stream().filter(AuthoritativeBearerFilter.class::isInstance).count());
            assertEquals(0,context.getBeanNamesForType(AuthoritativeBearerFilter.class).length);
            var f=context.getBean(AccountAccessAuthenticationProviderTest.Fixture.class);
            assertEquals(401,get(context,"/read",null).statusCode());
            assertEquals(200,get(context,"/read",f.token()).statusCode());
            assertEquals(1,f.reads.get());assertEquals(1,f.effects.get());
        }
    }
    @Test void duplicateServletRegistrationPreventsStartupBeforeTraffic(){
        assertThrows(IllegalArgumentException.class,()->server(Server.class,Duplicate.class));
    }
    @Test void actualForwardAndIncludeCannotTurnPublicAccessIntoProtectedExecution() throws Exception {
        try(var context=server(Server.class)){
            var f=context.getBean(AccountAccessAuthenticationProviderTest.Fixture.class);
            assertEquals(401,get(context,"/forward",null).statusCode());
            var included=get(context,"/include",null);
            assertEquals(500,included.statusCode());
            var body=new com.fasterxml.jackson.databind.ObjectMapper().readTree(included.body());
            assertEquals("SECURITY_INTERNAL_ERROR",body.get("code").asText());assertEquals(6,body.size());
            assertFalse(included.body().contains("ServletException"));assertFalse(included.body().contains("Included request"));
            assertEquals(0,f.effects.get());
            assertEquals(200,get(context,"/forward",f.token()).statusCode());
            assertEquals(200,get(context,"/include",f.token()).statusCode());
            assertEquals(2,f.effects.get());assertEquals(4,f.reads.get());
        }
    }
    @Test void actualAsyncDispatchPreservesWorkerIdentityAndRevalidates() throws Exception {
        try(var context=server(Server.class)){
            var f=context.getBean(AccountAccessAuthenticationProviderTest.Fixture.class);
            var reply=get(context,"/async",f.token());
            assertEquals(200,reply.statusCode());assertEquals("current-name",reply.body());assertEquals(2,f.reads.get());
        }
    }
}
