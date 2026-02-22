package com.JavaBruse.core.sniffer.grpc.retry;

import com.JavaBruse.core.exaption.ConnectionException;
import org.springframework.stereotype.Component;

@Component
public class Sleeper {

    public void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConnectionException("Interrupted during retry delay" + e);
        }
    }
}