package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.StatsRequest;
import com.JavaBruse.proto.StatsResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class StatsCommand extends GrpcCommand<String, StatsResponse> {

    public StatsCommand(SessionManager sessionManager) {
        super(sessionManager);
    }

    @Override
    protected StatsResponse executeWithSession(SessionInfo session, String period) {
        StatsRequest request = StatsRequest.newBuilder()
                .setSessionKey(session.getSessionKey())
                .setPeriod(period)
                .build();

        try {
            StatsResponse response = sessionManager.getStub(session).getStats(request);
            log.info("Stats retrieved for session: {}", session.getSessionKey());
            return response;
        } catch (Exception e) {
            handleError("stats", e);
            return null; // never reached
        }
    }
}