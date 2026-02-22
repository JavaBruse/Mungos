package com.JavaBruse.core.sniffer.grpc.retry;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class RetryStrategy {
    int maxAttempts;
    long initialDelayMs;
    long maxDelayMs;
    double backoffMultiplier;

    public static RetryStrategy defaultPingStrategy() {
        return RetryStrategy.builder()
                .maxAttempts(2)
                .initialDelayMs(1000)
                .maxDelayMs(5000)
                .backoffMultiplier(2.0)
                .build();
    }

    public static RetryStrategy defaultConnectionStrategy() {
        return RetryStrategy.builder()
                .maxAttempts(3)
                .initialDelayMs(500)
                .maxDelayMs(10000)
                .backoffMultiplier(2.0)
                .build();
    }
}
