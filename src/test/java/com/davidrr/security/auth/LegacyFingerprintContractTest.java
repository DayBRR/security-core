package com.davidrr.security.auth;

import com.davidrr.security.auth.dto.SessionFingerprint;
import com.davidrr.security.auth.util.*;
import com.davidrr.security.ratelimit.util.RateLimitKeyFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

class LegacyFingerprintContractTest {
    @Test
    void noProxyHeadersUsesRemoteAddressAndSuppliedUserAgent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.40");
        request.addHeader("User-Agent", "synthetic-agent");
        assertEquals(new SessionFingerprint("192.0.2.40", "synthetic-agent"), SessionFingerprint.from(request));
        assertEquals("192.0.2.40", FingerprintUtils.extractIp(request));
        assertEquals("synthetic-agent", FingerprintUtils.extractUserAgent(request));
    }

    @Test
    void absentUserAgentHasNeutralLegacyRepresentations() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertNull(SessionFingerprint.from(request).userAgent());
        assertEquals("unknown", FingerprintUtils.extractUserAgent(request));
    }

    @Test
    void rateLimitKeysAreDerivedFromFingerprintAddress() {
        RateLimitKeyFactory factory = new RateLimitKeyFactory();
        SessionFingerprint fingerprint = new SessionFingerprint("192.0.2.40", "synthetic-agent");
        assertEquals("192.0.2.40", factory.loginKey(fingerprint));
        assertEquals("192.0.2.40", factory.refreshKey(fingerprint));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "synthetic-unrecognized-agent", "Mozilla/5.0 Chrome/120.0 Windows", "curl/8.0"})
    void knownUnknownAndAbsentAgentsProduceNonblankDisplayLabels(String agent) {
        String label = assertDoesNotThrow(() -> UserAgentUtils.toDeviceLabel(agent));
        assertNotNull(label);
        assertFalse(label.isBlank());
        // No claim that a UA label authenticates identity, nor exact heuristic wording to freeze.
    }
}
