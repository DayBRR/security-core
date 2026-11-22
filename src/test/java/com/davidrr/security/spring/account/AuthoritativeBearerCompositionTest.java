package com.davidrr.security.spring.account;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthoritativeBearerCompositionTest {
    @org.springframework.context.annotation.Configuration(proxyBeanMethods=false)
    static class Required {
        @org.springframework.context.annotation.Bean
        AccountAccessAuthenticationProvider provider(com.davidrr.security.jwt.authoritative.AuthoritativeAccessTokenVerifier v,
                                                     AccessPrincipalMapper m,java.time.Clock c){return new AccountAccessAuthenticationProvider(v,m,c);}
        @org.springframework.context.annotation.Bean
        AuthoritativeBearerFilter filter(AccountAccessAuthenticationProvider p,AccountAuthenticationFailureHandler h,
                                         org.springframework.security.web.util.matcher.RequestMatcher m){return new AuthoritativeBearerFilter(p,h,m);}
    }
    static List<Filter> valid(AuthoritativeBearerFilter f){
        return List.of(new SecurityContextHolderFilter(new NullSecurityContextRepository()),f,
                new AnonymousAuthenticationFilter("fixture"),new AuthorizationFilter((a,r)->new org.springframework.security.authorization.AuthorizationDecision(true)));
    }
    static SecurityFilterChain chain(List<Filter> filters){return new DefaultSecurityFilterChain(r->true,filters);}
    @Test void minimalExplicitCompositionPassesButMissingDuplicateAndReorderedFiltersFail(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture().filter();var filters=valid(f);
        assertDoesNotThrow(()->AuthoritativeBearerComposition.validate(chain(filters),List.of()));
        for(int i=0;i<filters.size();i++){
            var missing=new ArrayList<>(filters);missing.remove(i);
            assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(missing),List.of()));
            var doubled=new ArrayList<>(filters);doubled.add(filters.get(i));
            assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(doubled),List.of()));
        }
        var reversed=new ArrayList<>(filters);Collections.reverse(reversed);
        assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(reversed),List.of()));
    }
    @Test void knownAlternativeAcceptorsAndStandaloneRegistrationAreRejected(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture().filter();
        for(Filter alternative:List.of(mock(com.davidrr.security.jwt.JwtAuthenticationFilter.class),mock(BasicAuthenticationFilter.class),
                mock(AuthenticationFilter.class),mock(RememberMeAuthenticationFilter.class))){
            var mixed=new ArrayList<>(valid(f));mixed.add(alternative);
            assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(mixed),List.of()));
            assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(valid(f)),List.of(alternative)));
        }
        assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(chain(valid(f)),List.of(f)));
    }
    @Test void noAutomaticActivationAndConstructionRequiresEveryCollaborator(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        assertThrows(NullPointerException.class,()->new AccountAccessAuthenticationProvider(null,s->null,f.clock));
        assertThrows(NullPointerException.class,()->new AccountAccessAuthenticationProvider(f.verifier(),null,f.clock));
        assertThrows(NullPointerException.class,()->new AccountAccessAuthenticationProvider(f.verifier(),s->null,null));
        assertThrows(NullPointerException.class,()->new AuthoritativeBearerFilter(null,f.writer(),r->true));
        assertThrows(NullPointerException.class,()->new AuthoritativeBearerFilter(f.provider(),null,r->true));
        assertThrows(NullPointerException.class,()->new AuthoritativeBearerFilter(f.provider(),f.writer(),null));
        var scanner=new org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new org.springframework.core.type.filter.AnnotationTypeFilter(org.springframework.stereotype.Component.class));
        for(var candidate:scanner.findCandidateComponents("com.davidrr.security.spring.account")) {
            // This package also contains the nested @Configuration fixtures on the test classpath.
            try {
                var origin=java.nio.file.Path.of(Class.forName(candidate.getBeanClassName()).getProtectionDomain().getCodeSource().getLocation().toURI());
                assertEquals(java.nio.file.Path.of("target/test-classes").toRealPath(),origin.toRealPath());
            } catch(Exception failure){throw new AssertionError(failure);}
        }
        new org.springframework.boot.test.context.runner.ApplicationContextRunner().run(c->assertEquals(0,c.getBeanNamesForType(AuthoritativeBearerFilter.class).length));
    }
    @Test void suppliedInventoryCannotProveUndeclaredContainerState(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture().filter();
        // Deliberately incomplete inventory passes the local check: server evidence must supply reality.
        assertDoesNotThrow(()->AuthoritativeBearerComposition.validate(chain(valid(f)),List.of()));
        assertThrows(NullPointerException.class,()->AuthoritativeBearerComposition.validate(chain(valid(f)),null));
    }
    @Test void activatedSpringWiringFailsForEachMissingCapabilityOrAmbiguousMapper(){
        for(int omitted=0;omitted<6;omitted++){
            var f=new AccountAccessAuthenticationProviderTest.Fixture();
            var runner=new org.springframework.boot.test.context.runner.ApplicationContextRunner().withUserConfiguration(Required.class);
            if(omitted!=0)runner=runner.withBean(com.davidrr.security.jwt.authoritative.AuthoritativeAccessTokenVerifier.class,f::verifier);
            if(omitted!=1)runner=runner.withBean(AccessPrincipalMapper.class,()->s->new MappedAccessPrincipal(s.identity(),AccountAccessAuthenticationProviderTest.Fixture.user(s)));
            if(omitted!=2)runner=runner.withBean(java.time.Clock.class,()->f.clock);
            if(omitted!=3)runner=runner.withBean(AccountAuthenticationFailureHandler.class,f::writer);
            if(omitted!=4)runner=runner.withBean(org.springframework.security.web.util.matcher.RequestMatcher.class,()->r->true);
            if(omitted==5)runner=runner.withBean("secondMapper",AccessPrincipalMapper.class,()->s->new MappedAccessPrincipal(s.identity(),AccountAccessAuthenticationProviderTest.Fixture.user(s)));
            runner.run(c->assertNotNull(c.getStartupFailure()));
        }
    }
    @Test void completeWiringNeedsNoRefreshJpaOrRegistrationPort(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        new org.springframework.boot.test.context.runner.ApplicationContextRunner().withUserConfiguration(Required.class)
                .withBean(com.davidrr.security.jwt.authoritative.AuthoritativeAccessTokenVerifier.class,f::verifier)
                .withBean(AccessPrincipalMapper.class,()->s->new MappedAccessPrincipal(s.identity(),AccountAccessAuthenticationProviderTest.Fixture.user(s)))
                .withBean(java.time.Clock.class,()->f.clock).withBean(AccountAuthenticationFailureHandler.class,f::writer)
                .withBean(org.springframework.security.web.util.matcher.RequestMatcher.class,()->r->true)
                .run(c->{assertNull(c.getStartupFailure());assertNotNull(c.getBean(AuthoritativeBearerFilter.class));});
    }
    @Test void disjointChainsAreValidButShadowingIsAnIntegratorObligation(){
        var f=new AccountAccessAuthenticationProviderTest.Fixture().filter();
        var authoritative=new DefaultSecurityFilterChain(r->r.getRequestURI().startsWith("/api/"),valid(f));
        var legacy=new DefaultSecurityFilterChain(r->r.getRequestURI().startsWith("/old/"),List.of(mock(com.davidrr.security.jwt.JwtAuthenticationFilter.class)));
        var request=new org.springframework.mock.web.MockHttpServletRequest("GET","/api/read");
        assertSame(authoritative,List.of(legacy,authoritative).stream().filter(c->c.matches(request)).findFirst().orElseThrow());
        assertDoesNotThrow(()->AuthoritativeBearerComposition.validate(authoritative,List.of()));
        var shadow=new DefaultSecurityFilterChain(r->true,List.of(mock(com.davidrr.security.jwt.JwtAuthenticationFilter.class)));
        var selected=List.of(shadow,authoritative).stream().filter(c->c.matches(request)).findFirst().orElseThrow();
        assertThrows(IllegalArgumentException.class,()->AuthoritativeBearerComposition.validate(selected,List.of()));
    }
}
