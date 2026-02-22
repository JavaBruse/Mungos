package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.PingRequest;
import com.JavaBruse.proto.PingResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class PingCommand extends GrpcCommand<String, String> {

    private static final String PING_MESSAGE = "ping from mungos-core";

    public PingCommand(SessionManager sessionManager) {
        super(sessionManager);
    }

    @Override
    protected String executeWithSession(SessionInfo session, String unused) {
        PingRequest request = PingRequest.newBuilder()
                .setSessionKey(session.getSessionKey())
                .setMessage(PING_MESSAGE)
                .build();

        try {
            PingResponse response = sessionManager.getStub(session).ping(request);
            log.info("Ping successful for session: {}", session.getSessionKey());
            return response.getMessage();
        } catch (Exception e) {
            handleError("ping", e);
            return null; // never reached
        }
    }
}