package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.UpdateConnectionInsightRequest;
import com.JavaBruse.proto.UpdateConnectionInsightResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UpdateConnectionInsightCommand {

    private final SessionManager sessionManager;

    public UpdateConnectionInsightResponse updateConnectionInsight(SnifferEntity sniffer, String packetId, String ja4EntryId, String sniEntryId) {
        return sessionManager.executeWithSession(sniffer, session -> {
            UpdateConnectionInsightRequest request = UpdateConnectionInsightRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .setPacketId(packetId)
                    .setJa4EntryId(ja4EntryId)
                    .setSniEntryId(sniEntryId)
                    .build();

            try {
                return sessionManager.getStub(session).updateConnectionInsight(request);
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