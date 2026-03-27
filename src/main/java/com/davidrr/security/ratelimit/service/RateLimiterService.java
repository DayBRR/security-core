package com.davidrr.security.ratelimit.service;

public interface RateLimiterService {

    void check(String bucket, String key);

    void onSuccess(String bucket, String key);

    void onFailure(String bucket, String key);
}