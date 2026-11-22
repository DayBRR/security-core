package com.davidrr.security.spring.account;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.access.AccessDeniedException;
import static org.junit.jupiter.api.Assertions.*;

class AccountAuthenticationFailureHandlerTest {
    @ParameterizedTest @ValueSource(ints={401,403,503,500})
    void fixedSixFieldErrorsExposeNoRequestOrExceptionData(int status) throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture();
        var request=new MockHttpServletRequest("GET","/private/identity-secret?jwt-secret");
        var reply=new MockHttpServletResponse(); var writer=f.writer();
        switch(status) {
            case 401 -> writer.commence(request,reply,new BadCredentialsException("exception-secret"));
            case 403 -> writer.handle(request,reply,new AccessDeniedException("exception-secret"));
            case 503 -> writer.write(request,reply,new AuthoritativeAuthenticationServiceException());
            default -> writer.writeUnexpectedFailure(request,reply);
        }
        assertEquals(status,reply.getStatus());
        var body=new com.fasterxml.jackson.databind.ObjectMapper().readTree(reply.getContentAsString());
        assertEquals(6,body.size()); assertEquals("/",body.get("path").asText()); assertEquals(status,body.get("status").asInt());
        String code=switch(status){case 401->"AUTH_UNAUTHORIZED";case 403->"AUTH_FORBIDDEN";case 503->"SECURITY_DEPENDENCY_UNAVAILABLE";default->"SECURITY_INTERNAL_ERROR";};
        assertEquals(code,body.get("code").asText());
        assertFalse(reply.getContentAsString().contains("secret"));
        assertEquals(status==401?"Bearer":null,reply.getHeader("WWW-Authenticate"));
        assertNull(reply.getHeader("Set-Cookie")); assertNull(reply.getHeader("Retry-After")); assertNull(reply.getHeader("Location"));
        assertTrue(reply.getContentType().startsWith("application/json"));
    }
    @Test void committedResponseIsUntouchedAndServiceFailureHasNoExternalCause() throws Exception {
        var f=new AccountAccessAuthenticationProviderTest.Fixture(); var reply=new MockHttpServletResponse();
        reply.getWriter().write("already-written"); reply.flushBuffer();
        f.writer().writeUnexpectedFailure(new MockHttpServletRequest(),reply);
        assertEquals("already-written",reply.getContentAsString()); assertEquals(200,reply.getStatus());
        assertNull(new AuthoritativeAuthenticationServiceException().getCause());
    }
}
