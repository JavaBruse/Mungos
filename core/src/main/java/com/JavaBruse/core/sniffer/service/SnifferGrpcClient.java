package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.proto.*;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
public class SnifferGrpcClient {

    @Value("${sniffer.master-key}")
    private String masterKey;

    private final ConcurrentHashMap<String, SnifferSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> lastReconnectAttempt = new ConcurrentHashMap<>();
    private static final long RECONNECT_COOLDOWN_MS = 10000; // 10 секунд между попытками переподключения

    static class SnifferSession {
        ManagedChannel channel;
        SnifferServiceGrpc.SnifferServiceBlockingStub stub;
        String sessionKey;
        String host;
        int port;
        String certificate;
        long lastUsed;

        void shutdown() {
            if (channel != null && !channel.isShutdown()) {
                channel.shutdown();
            }
        }

        void updateLastUsed() {
            this.lastUsed = System.currentTimeMillis();
        }
    }

    @FunctionalInterface
    public interface SessionCallback<T> {
        T execute(SnifferSession session) throws Exception;
    }

    public static class ConnectionResult {
        private final boolean success;
        private final boolean busy;
        private final String sessionKey;
        private final String certificate;
        private final String errorMessage;

        private ConnectionResult(boolean success, boolean busy, String sessionKey, String certificate, String errorMessage) {
            this.success = success;
            this.busy = busy;
            this.sessionKey = sessionKey;
            this.certificate = certificate;
            this.errorMessage = errorMessage;
        }

        public static ConnectionResult success(String sessionKey, String certificate) {
            return new ConnectionResult(true, false, sessionKey, certificate, null);
        }

        public static ConnectionResult failure(String errorMessage) {
            return new ConnectionResult(false, false, null, null, errorMessage);
        }

        public static ConnectionResult busy(String errorMessage) {
            return new ConnectionResult(false, true, null, null, errorMessage);
        }

        public boolean isSuccess() { return success; }
        public boolean isBusy() { return busy; }
        public String getSessionKey() { return sessionKey; }
        public String getCertificate() { return certificate; }
        public String getErrorMessage() { return errorMessage; }
    }

    public ConnectionResult connect(String host, int port, String existingSessionKey, String existingCertPEM) {
        String sessionId = host + ":" + port;

        // Проверяем cooldown для предотвращения зацикливания
        AtomicLong lastAttempt = lastReconnectAttempt.computeIfAbsent(sessionId, k -> new AtomicLong(0));
        long now = System.currentTimeMillis();
        long last = lastAttempt.get();

        if (now - last < RECONNECT_COOLDOWN_MS) {
            log.debug("Reconnect cooldown for {}, skipping", sessionId);
            return ConnectionResult.failure("Reconnect cooldown");
        }
        lastAttempt.set(now);

        // Проверяем существующую сессию
        SnifferSession existing = sessions.get(sessionId);
        if (existing != null) {
            try {
                PingRequest testRequest = PingRequest.newBuilder()
                        .setSessionKey(existing.sessionKey)
                        .setMessage("test")
                        .build();
                existing.stub.withDeadlineAfter(2, TimeUnit.SECONDS).ping(testRequest);
                log.info("Existing session is valid for {}", sessionId);
                existing.updateLastUsed();
                return ConnectionResult.success(existing.sessionKey, existing.certificate);
            } catch (Exception e) {
                log.info("Existing session invalid: {}", e.getMessage());
                existing.shutdown();
                sessions.remove(sessionId);
            }
        }

        // Пробуем восстановить сессию
        if (existingSessionKey != null) {
            try {
                ConnectionResult renewalResult = renewSession(host, port, existingSessionKey);
                if (renewalResult.isSuccess()) {
                    log.info("Session renewed for {}", sessionId);
                    return renewalResult;
                }
            } catch (Exception e) {
                log.warn("Session renewal failed: {}", e.getMessage());
            }
        }

        // Новая регистрация
        return registerNewClient(host, port, sessionId);
    }

    private ConnectionResult renewSession(String host, int port, String sessionKey) {
        ManagedChannel insecureChannel = null;
        try {
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            insecureChannel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(insecureSslContext)
                    .overrideAuthority("sniffer-server")
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub = SnifferServiceGrpc.newBlockingStub(insecureChannel);

            RegisterRequest request = RegisterRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .build();

            RegisterResponse response = insecureStub.withDeadlineAfter(10, TimeUnit.SECONDS)
                    .register(request);

            if (!response.getSuccess()) {
                return ConnectionResult.failure("Session renewal failed");
            }

            String newSessionKey = response.getSessionKey();
            String newCertPEM = response.getServerCertificate();

            if (newCertPEM == null || newCertPEM.isEmpty()) {
                return ConnectionResult.failure("No certificate received");
            }

            // Закрываем небезопасный канал
            insecureChannel.shutdown();
            insecureChannel = null;

            Thread.sleep(500);

            // Создаем защищенное соединение
            SnifferSession secureSession = createSessionWithCert(host, port, newCertPEM, newSessionKey);

            if (secureSession != null) {
                String sessionId = host + ":" + port;
                secureSession.host = host;
                secureSession.port = port;
                secureSession.certificate = newCertPEM;
                secureSession.updateLastUsed();
                sessions.put(sessionId, secureSession);
                return ConnectionResult.success(newSessionKey, newCertPEM);
            }

            return ConnectionResult.failure("Failed to create secure session");

        } catch (Exception e) {
            log.error("Session renewal error: {}", e.getMessage());
            return ConnectionResult.failure("Session renewal failed: " + e.getMessage());
        } finally {
            if (insecureChannel != null) {
                insecureChannel.shutdown();
            }
        }
    }

    private ConnectionResult registerNewClient(String host, int port, String sessionId) {
        ManagedChannel insecureChannel = null;
        try {
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            insecureChannel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(insecureSslContext)
                    .overrideAuthority("sniffer-server")
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub = SnifferServiceGrpc.newBlockingStub(insecureChannel);

            RegisterRequest request = RegisterRequest.newBuilder()
                    .setMasterKey(masterKey)
                    .setSnifferId("java-server-" + System.currentTimeMillis())
                    .build();

            RegisterResponse response = insecureStub.withDeadlineAfter(10, TimeUnit.SECONDS)
                    .register(request);

            if (!response.getSuccess()) {
                return ConnectionResult.failure("Registration failed");
            }

            String sessionKey = response.getSessionKey();
            String certPEM = response.getServerCertificate();

            if (certPEM == null || certPEM.isEmpty()) {
                return ConnectionResult.failure("No certificate received");
            }

            log.info("New registration successful");
            insecureChannel.shutdown();
            insecureChannel = null;

            Thread.sleep(500);

            SnifferSession secureSession = createSessionWithCert(host, port, certPEM, sessionKey);

            if (secureSession != null) {
                secureSession.host = host;
                secureSession.port = port;
                secureSession.certificate = certPEM;
                secureSession.updateLastUsed();
                sessions.put(sessionId, secureSession);
                return ConnectionResult.success(sessionKey, certPEM);
            }

            return ConnectionResult.failure("Failed to create secure session");

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.ALREADY_EXISTS) {
                return ConnectionResult.busy("Sniffer is busy with another client");
            }
            log.error("gRPC error: {}", e.getMessage());
            return ConnectionResult.failure("Connection failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Connection error: {}", e.getMessage());
            return ConnectionResult.failure("Connection failed: " + e.getMessage());
        } finally {
            if (insecureChannel != null) {
                insecureChannel.shutdown();
            }
        }
    }

    public ConnectionResult connect(String host, int port) {
        return connect(host, port, null, null);
    }

    public <T> T execute(String host, int port, SessionCallback<T> callback) {
        String sessionId = host + ":" + port;
        SnifferSession session = sessions.get(sessionId);

        if (session == null) {
            throw new ConnectionException("No active session for " + sessionId);
        }

        try {
            T result = callback.execute(session);
            session.updateLastUsed();
            return result;
        } catch (StatusRuntimeException e) {
            // Ошибка соединения - удаляем сессию
            if (e.getStatus().getCode() == Status.Code.UNAVAILABLE ||
                    e.getStatus().getCode() == Status.Code.UNAUTHENTICATED ||
                    e.getStatus().getCode() == Status.Code.DEADLINE_EXCEEDED) {

                log.warn("Connection error for {}: {}, removing session", sessionId, e.getStatus().getCode());
                sessions.remove(sessionId);
                session.shutdown();
                throw new ConnectionException("Connection lost: " + e.getMessage());
            }
            throw new ServiceException("gRPC error: " + e.getMessage());
        } catch (Exception e) {
            throw new ServiceException("Operation failed: " + e.getMessage());
        }
    }

    public boolean isConnected(String host, int port) {
        SnifferSession session = sessions.get(host + ":" + port);
        if (session == null) return false;

        try {
            PingRequest testRequest = PingRequest.newBuilder()
                    .setSessionKey(session.sessionKey)
                    .setMessage("test")
                    .build();
            session.stub.withDeadlineAfter(2, TimeUnit.SECONDS).ping(testRequest);
            session.updateLastUsed();
            return true;
        } catch (Exception e) {
            sessions.remove(host + ":" + port);
            session.shutdown();
            return false;
        }
    }

    public void disconnect(String host, int port) {
        String sessionId = host + ":" + port;
        SnifferSession session = sessions.remove(sessionId);
        lastReconnectAttempt.remove(sessionId);
        if (session != null) {
            session.shutdown();
            log.info("Disconnected from {}", sessionId);
        }
    }

    private SnifferSession createSessionWithCert(String host, int port, String certPEM, String sessionKey) {
        try {
            X509Certificate serverCert = parseCertificate(certPEM);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("server", serverCert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SslContext sslContext = GrpcSslContexts.forClient()
                    .trustManager(tmf)
                    .build();

            ManagedChannel channel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(sslContext)
                    .overrideAuthority("sniffer-server")
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub stub = SnifferServiceGrpc.newBlockingStub(channel);

            // Проверяем соединение
            PingRequest pingRequest = PingRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .setMessage("test")
                    .build();

            PingResponse pingResponse = stub.withDeadlineAfter(5, TimeUnit.SECONDS).ping(pingRequest);
            log.info("Secure session verified, ping response: {}", pingResponse.getMessage());

            SnifferSession session = new SnifferSession();
            session.channel = channel;
            session.stub = stub;
            session.sessionKey = sessionKey;
            session.certificate = certPEM;
            session.updateLastUsed();

            return session;

        } catch (Exception e) {
            log.error("Failed to create secure session: {}", e.getMessage());
            return null;
        }
    }

    private X509Certificate parseCertificate(String certPEM) throws Exception {
        String certContent = certPEM
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(certContent);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = new ByteArrayInputStream(certBytes)) {
            return (X509Certificate) cf.generateCertificate(is);
        }
    }

    @PreDestroy
    public void shutdown() {
        sessions.values().forEach(SnifferSession::shutdown);
        sessions.clear();
        lastReconnectAttempt.clear();
    }
}