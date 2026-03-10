package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.SettingRequest;
import com.JavaBruse.proto.SettingResponse;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class SettingCommand extends GrpcCommand<SettingRequest, SettingResponse> {

    public SettingCommand(SessionManager sessionManager) {
        super(sessionManager);
    }

    @Override
    protected SettingResponse executeWithSession(SessionInfo session, SettingRequest request) {
        throw new UnsupportedOperationException("Use getSettings or setSettings methods");
    }

    public SettingResponse getSettings(SnifferEntity sniffer) {
        SettingRequest request = SettingRequest.newBuilder().build();
        return execute(sniffer, request);
    }

    public SettingResponse setSettings(SnifferEntity sniffer, List<String> filters) {
        SettingRequest request = SettingRequest.newBuilder()
                .addAllFilters(filters)
                .build();
        return execute(sniffer, request);
    }

    public SettingResponse execute(SnifferEntity sniffer, SettingRequest request) {
        return sessionManager.executeWithSession(sniffer, session -> {
            SettingRequest protoRequest = SettingRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .addAllFilters(request.getFiltersList())
                    .build();

            try {
                if (request.getFiltersCount() > 0) {
                    return sessionManager.getStub(session).setSettings(protoRequest);
                } else {
                    return sessionManager.getStub(session).getSettings(protoRequest);
                }
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