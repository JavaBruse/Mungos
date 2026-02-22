package com.JavaBruse.core.sniffer.grpc.retry;

import com.JavaBruse.core.exaption.ConnectionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.function.Predicate;

@Slf4j
@Component
@RequiredArgsConstructor
public class RetryPolicy {

    private final Sleeper sleeper;

    public <T> T executeWithRetry(RetryStrategy strategy,
                                  SupplierWithException<T> action,
                                  Predicate<Exception> shouldRetry,
                                  String operationName) {

        int attempt = 0;
        long delay = strategy.getInitialDelayMs();
        Exception lastException = null;

        while (attempt < strategy.getMaxAttempts()) {
            try {
                return action.get();
            } catch (Exception e) {
                lastException = e;
                attempt++;

                if (attempt >= strategy.getMaxAttempts() || !shouldRetry.test(e)) {
                    log.error("Operation {} failed after {} attempts", operationName, attempt);
                    break;
                }

                log.info("Operation {} failed (attempt {}/{}), retrying in {}ms",
                        operationName, attempt, strategy.getMaxAttempts(), delay);

                sleeper.sleep(delay);
                delay = Math.min((long)(delay * strategy.getBackoffMultiplier()),
                        strategy.getMaxDelayMs());
            }
        }

        throw new ConnectionException("Operation " + operationName + " failed" + lastException);
    }

    @FunctionalInterface
    public interface SupplierWithException<T> {
        T get() throws Exception;
    }
}
