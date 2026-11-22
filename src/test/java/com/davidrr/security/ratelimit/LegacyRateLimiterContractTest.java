package com.davidrr.security.ratelimit;

import com.davidrr.security.ratelimit.config.RateLimitProperties;
import com.davidrr.security.ratelimit.exception.RateLimitExceededException;
import com.davidrr.security.ratelimit.service.InMemoryRateLimiterService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/** Legacy failure counter only. Exact window expiration/Clock and atomic admission belong to PR 05. */
class LegacyRateLimiterContractTest {
    private final RateLimitProperties properties = new RateLimitProperties();
    private final InMemoryRateLimiterService limiter = new InMemoryRateLimiterService(properties);

    @ParameterizedTest
    @ValueSource(strings = {"login", "refresh"})
    void checksDoNotConsumeFailureBudgetAndThresholdBlocksAfterFailures(String bucket) {
        configure(bucket).setMaxAttempts(2);
        configure(bucket).setWindowSeconds(3600);
        for (int i = 0; i < 10; i++) assertDoesNotThrow(() -> limiter.check(bucket, "fixture-key"));
        limiter.onFailure(bucket, "fixture-key");
        assertDoesNotThrow(() -> limiter.check(bucket, "fixture-key"));
        limiter.onFailure(bucket, "fixture-key");
        assertThrows(RateLimitExceededException.class, () -> limiter.check(bucket, "fixture-key"));
        limiter.onSuccess(bucket, "fixture-key");
        assertDoesNotThrow(() -> limiter.check(bucket, "fixture-key"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"login", "refresh"})
    void disabledBucketDoesNotAccumulateFailuresOrBlock(String bucket) {
        configure(bucket).setEnabled(false);
        configure(bucket).setMaxAttempts(1);
        for (int i = 0; i < 10; i++) limiter.onFailure(bucket, "fixture-key");
        assertDoesNotThrow(() -> limiter.check(bucket, "fixture-key"));
        configure(bucket).setEnabled(true);
        assertDoesNotThrow(() -> limiter.check(bucket, "fixture-key"));
    }

    @Test
    void countersAreIsolatedByBucketAndKey() {
        properties.getLogin().setMaxAttempts(1);
        properties.getRefresh().setMaxAttempts(1);
        properties.getLogin().setWindowSeconds(3600);
        properties.getRefresh().setWindowSeconds(3600);
        limiter.onFailure("login", "one");
        assertThrows(RateLimitExceededException.class, () -> limiter.check("login", "one"));
        assertDoesNotThrow(() -> limiter.check("login", "two"));
        assertDoesNotThrow(() -> limiter.check("refresh", "one"));
        limiter.onSuccess("refresh", "one");
        assertThrows(RateLimitExceededException.class, () -> limiter.check("login", "one"));
    }

    @Test
    void unknownBucketCannotBeCheckedOrCharged() {
        assertThrows(IllegalArgumentException.class, () -> limiter.check("unknown", "fixture-key"));
        assertThrows(IllegalArgumentException.class, () -> limiter.onFailure("unknown", "fixture-key"));
    }

    private RateLimitProperties.Bucket configure(String bucket) {
        return bucket.equals("login") ? properties.getLogin() : properties.getRefresh();
    }
}
