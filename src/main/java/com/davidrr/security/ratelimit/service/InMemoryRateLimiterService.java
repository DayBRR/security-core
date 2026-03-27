package com.davidrr.security.ratelimit.service;

import com.davidrr.security.ratelimit.config.RateLimitProperties;
import com.davidrr.security.ratelimit.exception.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class InMemoryRateLimiterService implements RateLimiterService {

    private final RateLimitProperties properties;
    private final Map<String, Counter> counters = new ConcurrentHashMap<>();

    @Override
    public void check(String bucket, String key) {
        RateLimitProperties.Bucket config = resolveBucket(bucket);

        if (!config.isEnabled()) {
            return;
        }

        String mapKey = buildKey(bucket, key);
        Counter counter = counters.get(mapKey);

        if (counter == null) {
            return;
        }

        Instant now = Instant.now();

        if (now.isAfter(counter.windowEnd)) {
            counters.remove(mapKey);
            return;
        }

        if (counter.attempts >= config.getMaxAttempts()) {
            throw new RateLimitExceededException();
        }
    }

    @Override
    public void onSuccess(String bucket, String key) {
        counters.remove(buildKey(bucket, key));
    }

    @Override
    public void onFailure(String bucket, String key) {
        RateLimitProperties.Bucket config = resolveBucket(bucket);

        if (!config.isEnabled()) {
            return;
        }

        String mapKey = buildKey(bucket, key);
        Instant now = Instant.now();

        counters.compute(mapKey, (k, existing) -> {
            if (existing == null || now.isAfter(existing.windowEnd)) {
                return new Counter(1, now.plusSeconds(config.getWindowSeconds()));
            }

            existing.attempts++;
            return existing;
        });
    }

    private RateLimitProperties.Bucket resolveBucket(String bucket) {
        return switch (bucket) {
            case RateLimitProperties.Bucket.LOGIN -> properties.getLogin();
            case RateLimitProperties.Bucket.REFRESH -> properties.getRefresh();
            default -> throw new IllegalArgumentException("Unknown rate limit bucket: " + bucket);
        };
    }

    private String buildKey(String bucket, String key) {
        return bucket + ":" + key;
    }

    private static class Counter {
        private int attempts;
        private final Instant windowEnd;

        private Counter(int attempts, Instant windowEnd) {
            this.attempts = attempts;
            this.windowEnd = windowEnd;
        }
    }
}