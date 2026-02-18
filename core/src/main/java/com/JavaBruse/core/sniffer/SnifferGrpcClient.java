package com.JavaBruse.core.sniffer;

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

@Slf4j
@Service
public class SnifferGrpcClient {

    @Value("${sniffer.master-key}")
    private String masterKey;

    private final ConcurrentHashMap<String, SnifferSession> sessions = new ConcurrentHashMap<>();

    private static class SnifferSession {
        ManagedChannel channel;
        SnifferServiceGrpc.SnifferServiceBlockingStub stub;
        String sessionKey;
        X509Certificate serverCertificate;
        boolean isSecureConnection;

        void shutdown() {
            if (channel != null && !channel.isShutdown()) {
                channel.shutdown();
            }
        }
    }

    public boolean connect(String host, int port) {
        String sessionId = host + ":" + port;

        // Проверяем существующую сессию
        SnifferSession existingSession = sessions.get(sessionId);
        if (existingSession != null) {
            try {
                PingRequest testRequest = PingRequest.newBuilder()
                        .setSessionKey(existingSession.sessionKey)
                        .setMessage("test")
                        .build();

                existingSession.stub.withDeadlineAfter(2, TimeUnit.SECONDS).ping(testRequest);
                log.info("Existing session is alive for {}", sessionId);
                return true;
            } catch (Exception e) {
                log.info("Existing session dead, removing: {}", sessionId);
                existingSession.shutdown();
                sessions.remove(sessionId);
            }
        }

        // Создаем новую сессию
        try {
            log.info("Creating new session for {}:{}", host, port);

            // 1. Небезопасное соединение для получения сертификата
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            ManagedChannel insecureChannel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(insecureSslContext)
                    .overrideAuthority("any-host-name")
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub = SnifferServiceGrpc.newBlockingStub(insecureChannel);

            // Регистрация с master key
            RegisterRequest request = RegisterRequest.newBuilder()
                    .setMasterKey(masterKey)
                    .setSnifferId("java-server-" + System.currentTimeMillis())
                    .build();

            RegisterResponse response = insecureStub.withDeadlineAfter(10, TimeUnit.SECONDS)
                    .register(request);

            if (!response.getSuccess()) {
                log.error("Registration failed: {}", response.getMessage());
                insecureChannel.shutdown();
                return false;
            }

            String sessionKey = response.getSessionKey();
            String certPEM = response.getServerCertificate();

            if (certPEM == null || certPEM.isEmpty()) {
                log.error("No certificate received from server");
                insecureChannel.shutdown();
                return false;
            }

            // Сохраняем сертификат
            X509Certificate serverCert = parseCertificate(certPEM);

            // Закрываем небезопасное соединение
            insecureChannel.shutdown();

            // Создаем защищенное соединение
            SnifferSession secureSession = createSecureSession(host, port, serverCert, sessionKey);

            if (secureSession != null) {
                sessions.put(sessionId, secureSession);
                log.info("Secure session established for {}", sessionId);
                return true;
            }

            return false;

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.ALREADY_EXISTS) {
                log.warn("Sniffer at {}:{} already has a client. This client cannot connect.", host, port);
                // Можно сохранить какой-то флаг, что сниффер занят
                return false;
            }
            log.error("Failed to connect to sniffer {}:{}", host, port, e);
            return false;
        } catch (Exception e) {
            log.error("Failed to connect to sniffer {}:{}", host, port, e);
            return false;
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
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            log.info("Server certificate saved: {}", cert.getSubjectDN());
            return cert;
        }
    }

    private SnifferSession createSecureSession(String host, int port, X509Certificate serverCert, String sessionKey) {
        try {
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
                    .overrideAuthority(host)
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub stub = SnifferServiceGrpc.newBlockingStub(channel);

            // Проверяем соединение
            PingRequest pingRequest = PingRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .setMessage("test")
                    .build();

            PingResponse pingResponse = stub.withDeadlineAfter(5, TimeUnit.SECONDS)
                    .ping(pingRequest);

            log.info("Secure connection verified: {}", pingResponse.getMessage());

            SnifferSession session = new SnifferSession();
            session.channel = channel;
            session.stub = stub;
            session.sessionKey = sessionKey;
            session.serverCertificate = serverCert;
            session.isSecureConnection = true;

            return session;

        } catch (Exception e) {
            log.error("Failed to create secure session", e);
            return null;
        }
    }

    public String ping(String host, int port) {
        return executeWithSession(host, port, session -> {
            PingRequest request = PingRequest.newBuilder()
                    .setSessionKey(session.sessionKey)
                    .setMessage("ping from Java")
                    .build();
            return session.stub.ping(request).getMessage();
        });
    }

    public StatsResponse getStats(String host, int port, String period) {
        return executeWithSession(host, port, session -> {
            StatsRequest request = StatsRequest.newBuilder()
                    .setSessionKey(session.sessionKey)
                    .setPeriod(period)
                    .build();
            return session.stub.getStats(request);
        });
    }

    @PreDestroy
    public void shutdown() {
        sessions.values().forEach(SnifferSession::shutdown);
        sessions.clear();
    }

    public boolean isConnected(String host, int port) {
        SnifferSession session = sessions.get(host + ":" + port);
        return session != null &&
                session.channel != null &&
                !session.channel.isShutdown() &&
                session.sessionKey != null;
    }

    private SnifferSession getOrCreateSession(String host, int port) {
        String sessionId = host + ":" + port;
        SnifferSession session = sessions.get(sessionId);

        if (session != null) {
            return session;
        }

        // Пытаемся подключиться
        boolean connected = connect(host, port);
        if (!connected) {
            throw new RuntimeException("SNIFFER_BUSY_OR_UNAVAILABLE");
        }

        session = sessions.get(sessionId);
        if (session == null) {
            throw new RuntimeException("CONNECTION_FAILED");
        }

        return session;
    }

    private <T> T executeWithSession(String host, int port, SessionCallback<T> callback) {
        String sessionId = host + ":" + port;
        SnifferSession session = null;

        try {
            session = getOrCreateSession(host, port);
            return callback.execute(session);

        } catch (RuntimeException e) {
            if ("SNIFFER_BUSY_OR_UNAVAILABLE".equals(e.getMessage())) {
                log.warn("Sniffer busy: {}:{}", host, port);
                throw new BusyException("Sniffer is busy with another client");
            }
            if ("CONNECTION_FAILED".equals(e.getMessage())) {
                log.warn("Connection failed: {}:{}", host, port);
                throw new ConnectionException("Failed to establish connection");
            }
            log.error("Unexpected error for {}: {}", sessionId, e.getMessage());
            throw new ServiceException("Service error: " + e.getMessage());

        } catch (Exception e) {
            log.error("Operation failed for {}: {}", sessionId, e.getMessage());
            SnifferSession dead = sessions.remove(sessionId);
            if (dead != null) dead.shutdown();
            throw new ServiceException("Service unavailable");
        }
    }

    class BusyException extends RuntimeException {
        public BusyException(String msg) { super(msg); }
    }
    class ConnectionException extends RuntimeException {
        public ConnectionException(String msg) { super(msg); }
    }
    class ServiceException extends RuntimeException {
        public ServiceException(String msg) { super(msg); }
    }

    @FunctionalInterface
    private interface SessionCallback<T> {
        T execute(SnifferSession session) throws Exception;
    }
}