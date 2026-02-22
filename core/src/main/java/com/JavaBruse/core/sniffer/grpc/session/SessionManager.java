package com.JavaBruse.core.sniffer.grpc.session;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.grpc.client.ConnectionResult;
import com.JavaBruse.core.sniffer.grpc.client.GrpcConnectionManager;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.proto.SnifferServiceGrpc;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class SessionManager {

    private final GrpcConnectionManager connectionManager;
    private final SnifferRepository snifferRepository;
    private final ConcurrentHashMap<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();

    public <T> T executeWithSession(String snifferId, SessionInfo.SessionCallback<T> callback) {
        SnifferEntity sniffer = snifferRepository.findById(snifferId)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + snifferId));

        return executeWithSession(sniffer, callback);
    }

    public <T> T executeWithSession(SnifferEntity sniffer, SessionInfo.SessionCallback<T> callback) {
        String sessionKey = buildSessionKey(sniffer);
        SessionInfo session = getOrCreateSession(sniffer, sessionKey);

        try {
            T result = callback.execute(session);
            updateSessionSuccess(sniffer, session);
            return result;
        } catch (Exception e) {
            handleSessionError(sniffer, sessionKey, e);
            throw e;
        }
    }

    private SessionInfo getOrCreateSession(SnifferEntity sniffer, String sessionKey) {
        SessionInfo session = activeSessions.get(sessionKey);
        return session != null ? session : createNewSession(sniffer, sessionKey);
    }

    private SessionInfo createNewSession(SnifferEntity sniffer, String sessionKey) {
        ConnectionResult result = connectionManager.connect(
                sniffer.getHost(),
                sniffer.getPort(),
                sniffer.getSessionKey(),
                sniffer.getCertificate()
        );

        if (!result.isSuccess()) {
            throw new ConnectionException("Failed to create session: " + result.getErrorMessage());
        }

        SessionInfo session = SessionInfo.builder()
                .sessionKey(result.getSessionKey())
                .certificate(result.getCertificate())
                .host(sniffer.getHost())
                .port(sniffer.getPort())
                .build();

        activeSessions.put(sessionKey, session);
        return session;
    }

    private void updateSessionSuccess(SnifferEntity sniffer, SessionInfo session) {

        sniffer.setConnected(true);
        sniffer.updateLastSeen();
        sniffer.setSessionKey(session.getSessionKey());

        if (session.getCertificate() != null) {
            sniffer.setCertificate(session.getCertificate());
        }

        snifferRepository.save(sniffer);
    }

    private void handleSessionError(SnifferEntity sniffer, String sessionKey, Exception e) {
        log.error("Session error for sniffer {}: {}", sniffer.getId(), e.getMessage());

        if (isConnectionError(e)) {
            activeSessions.remove(sessionKey);
            connectionManager.disconnect(sniffer.getHost(), sniffer.getPort());
            sniffer.setConnected(false);
            snifferRepository.save(sniffer);
        }
    }

    private boolean isConnectionError(Exception e) {
        return e instanceof ConnectionException ||
                (e instanceof StatusRuntimeException &&
                        (Status.fromThrowable(e).getCode() == Status.Code.UNAVAILABLE ||
                                Status.fromThrowable(e).getCode() == Status.Code.UNAUTHENTICATED));
    }

    private String buildSessionKey(SnifferEntity sniffer) {
        return sniffer.getHost() + ":" + sniffer.getPort();
    }

    public SnifferServiceGrpc.SnifferServiceBlockingStub getStub(SessionInfo session) {
        return connectionManager.getStub(session.getHost(), session.getPort());
    }

    public boolean isConnected(SnifferEntity sniffer) {
        return connectionManager.isConnected(sniffer.getHost(), sniffer.getPort());
    }

    public void invalidateSession(SnifferEntity sniffer) {
        String sessionKey = buildSessionKey(sniffer);
        activeSessions.remove(sessionKey);
        connectionManager.disconnect(sniffer.getHost(), sniffer.getPort());
    }

    public ConnectionResult createConnection(String host, int port, String sessionKey, String certificate) {
        return connectionManager.connect(host, port, sessionKey, certificate);
    }

    @PreDestroy
    public void shutdown() {
        activeSessions.clear();
        connectionManager.shutdown();
    }
}
