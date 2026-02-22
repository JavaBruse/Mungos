package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public abstract class GrpcCommand<T, R> {

    protected final SessionManager sessionManager;

    public R execute(SnifferEntity sniffer, T request) {
        return sessionManager.executeWithSession(sniffer, session -> executeWithSession(session, request));
    }

    protected abstract R executeWithSession(SessionInfo session, T request);

    protected void handleError(String operation, Exception e) {
        log.error("{} execution failed: {}", operation, e.getMessage());
        throw new ConnectionException("Failed to execute " + operation + ": " + e.getMessage());
    }
}