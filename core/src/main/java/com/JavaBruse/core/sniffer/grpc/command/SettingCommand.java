package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.SettingRequest;
import com.JavaBruse.proto.SettingResponse;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SettingCommand {

    private final SessionManager sessionManager;

    public SettingResponse getSettings(SnifferEntity sniffer) {
        return sessionManager.executeWithSession(sniffer, session -> {
            SettingRequest protoRequest = SettingRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .build();

            try {
                return sessionManager.getStub(session).getSettings(protoRequest);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost to sniffer", e);
                    throw new ConnectionException("Connection lost");
                }
                throw e;
            }
        });
    }

    public SettingResponse setSettings(SnifferEntity sniffer, String filters) {
        return sessionManager.executeWithSession(sniffer, session -> {
            SettingRequest protoRequest = SettingRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .setFilters(filters)
                    .build();

            try {
                return sessionManager.getStub(session).setSettings(protoRequest);
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