package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.ConnectionInsight;
import com.JavaBruse.proto.ConnectionInsightRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import io.grpc.StatusRuntimeException;
import io.grpc.Status;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class ConnectionInsightCommand {

    private final SessionManager sessionManager;

    public ConnectionInsight getConnectionInsight(SnifferEntity sniffer, String packetId) {
        return sessionManager.executeWithSession(sniffer, session -> {
            ConnectionInsightRequest protoRequest = ConnectionInsightRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .setPacketId(packetId)
                    .build();

            try {
                return sessionManager.getStub(session).getConnectionInsight(protoRequest);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost to sniffer", e);
                    throw new ConnectionException("Connection lost");
                }
                throw e;
            }
        });
    }
}