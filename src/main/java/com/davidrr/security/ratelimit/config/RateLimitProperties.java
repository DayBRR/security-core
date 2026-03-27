package com.davidrr.security.ratelimit.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@Setter
@Getter
@ConfigurationProperties(prefix = "security.rate-limit")
public class RateLimitProperties {

    private Bucket login = new Bucket();
    private Bucket refresh = new Bucket();

    @Setter
    @Getter
    public static class Bucket {
        public static final String LOGIN = "login";
        public static final String REFRESH = "refresh";
        private boolean enabled = true;
        private int maxAttempts = 5;
        private long windowSeconds = 60;
    }
}
