package com.davidrr.security.ratelimit.util;

import com.davidrr.security.auth.dto.SessionFingerprint;
import org.springframework.stereotype.Component;

@Component
public class RateLimitKeyFactory {

    public String loginKey(SessionFingerprint fingerprint) {
        return fingerprint.ip();
    }

    public String refreshKey(SessionFingerprint fingerprint) {
        return fingerprint.ip();
    }
}
