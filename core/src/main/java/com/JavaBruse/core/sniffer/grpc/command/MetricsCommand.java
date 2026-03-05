package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.MetricsRequest;
import com.JavaBruse.proto.MetricsResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class MetricsCommand extends GrpcCommand<String, MetricsResponse> {

    public MetricsCommand(SessionManager sessionManager) {
        super(sessionManager);
    }

    @Override
    protected MetricsResponse executeWithSession(SessionInfo session, String period) {
        MetricsRequest request = MetricsRequest.newBuilder()
                .setSessionKey(session.getSessionKey())
                .build();

        try {
            MetricsResponse response = sessionManager.getStub(session).getMetrics(request);
            log.info("Metrics retrieved for session: {}", session.getSessionKey());
            return response;
        } catch (Exception e) {
            handleError("metrics", e);
            return null;
        }
    }
}