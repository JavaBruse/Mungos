package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.proto.FilterExpression;
import com.JavaBruse.proto.PayloadRequest;
import com.JavaBruse.proto.TrafficFilterRequest;
import com.JavaBruse.proto.TrafficPacket;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Iterator;

@Slf4j
@Component
public class TrafficCommand extends GrpcCommand<TrafficCommand.TrafficRequest, Iterator<TrafficPacket>> {

    public TrafficCommand(SessionManager sessionManager) {
        super(sessionManager);
    }

    @Override
    protected Iterator<TrafficPacket> executeWithSession(SessionInfo session, TrafficRequest request) {
        TrafficFilterRequest protoRequest = TrafficFilterRequest.newBuilder()
                .setSessionKey(session.getSessionKey())
                .setFilter(request.getFilter())
                .setLimit(request.getLimit())
                .setOffset(request.getOffset())
                .build();

        try {
            return sessionManager.getStub(session)
                    .getFilteredTraffic(protoRequest);
        } catch (Exception e) {
            handleError("traffic stream", e);
            return null; // never reached
        }
    }

    @Value
    @Builder
    public static class TrafficRequest {
        FilterExpression filter;
        int limit;
        int offset;
    }

    public byte[] getPayload(SnifferEntity sniffer, String packetId) {
        return sessionManager.executeWithSession(sniffer, session -> {
            PayloadRequest protoRequest = PayloadRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .setPacketId(packetId)
                    .build();

            return sessionManager.getStub(session)
                    .getPacketPayload(protoRequest)
                    .getPayload()
                    .toByteArray();
        });
    }
}