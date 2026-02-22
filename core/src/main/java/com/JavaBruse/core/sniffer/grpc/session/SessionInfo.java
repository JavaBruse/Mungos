package com.JavaBruse.core.sniffer.grpc.session;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SessionInfo {
    private final String sessionKey;
    private final String certificate;
    private final String host;
    private final int port;



    @FunctionalInterface
    public interface SessionCallback<T> {
        T execute(SessionInfo session);
    }
}