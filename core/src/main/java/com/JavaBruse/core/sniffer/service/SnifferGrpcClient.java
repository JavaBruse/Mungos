package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.BusyException;
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

@Slf4j
@Service
public class SnifferGrpcClient {

    @Value("${sniffer.master-key}")
    private String masterKey;

    private final ConcurrentHashMap<String, SnifferSession> sessions = new ConcurrentHashMap<>();

    static class SnifferSession {
        ManagedChannel channel;
        SnifferServiceGrpc.SnifferServiceBlockingStub stub;
        String sessionKey;
        X509Certificate serverCertificate;
        String host;
        int port;

        void shutdown() {
            if (channel != null && !channel.isShutdown()) {
                channel.shutdown();
            }
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

        SnifferSession existing = sessions.get(sessionId);
        if (existing != null) {
            try {
                PingRequest testRequest = PingRequest.newBuilder()
                        .setSessionKey(existing.sessionKey)
                        .setMessage("test")
                        .build();
                existing.stub.withDeadlineAfter(2, TimeUnit.SECONDS).ping(testRequest);
                return ConnectionResult.success(existing.sessionKey, getCertificateAsPEM(existing.serverCertificate));
            } catch (Exception e) {
                existing.shutdown();
                sessions.remove(sessionId);
            }
        }

        if (existingSessionKey != null && existingCertPEM != null) {
            try {
                X509Certificate serverCert = parseCertificate(existingCertPEM);
                SnifferSession restoredSession = createSecureSession(host, port, serverCert, existingSessionKey);
                if (restoredSession != null) {
                    restoredSession.host = host;
                    restoredSession.port = port;
                    sessions.put(sessionId, restoredSession);
                    return ConnectionResult.success(existingSessionKey, existingCertPEM);
                }
            } catch (Exception e) {
                log.info("Failed to reuse existing session for {}", sessionId);
            }
        }

        try {
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            ManagedChannel insecureChannel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(insecureSslContext)
                    .overrideAuthority("any-host-name")
                    .build();

            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub = SnifferServiceGrpc.newBlockingStub(insecureChannel);

            RegisterRequest request = RegisterRequest.newBuilder()
                    .setMasterKey(masterKey)
                    .setSnifferId("java-server-" + System.currentTimeMillis())
                    .build();

            RegisterResponse response = insecureStub.withDeadlineAfter(10, TimeUnit.SECONDS)
                    .register(request);

            if (!response.getSuccess()) {
                insecureChannel.shutdown();
                return ConnectionResult.failure("Registration failed");
            }

            String sessionKey = response.getSessionKey();
            String certPEM = response.getServerCertificate();

            if (certPEM == null || certPEM.isEmpty()) {
                insecureChannel.shutdown();
                return ConnectionResult.failure("No certificate received");
            }

            X509Certificate serverCert = parseCertificate(certPEM);
            insecureChannel.shutdown();

            SnifferSession secureSession = createSecureSession(host, port, serverCert, sessionKey);

            if (secureSession != null) {
                secureSession.host = host;
                secureSession.port = port;
                sessions.put(sessionId, secureSession);
                return ConnectionResult.success(sessionKey, certPEM);
            }

            return ConnectionResult.failure("Failed to create secure session");

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.ALREADY_EXISTS) {
                return ConnectionResult.busy("Sniffer is busy with another client");
            }
            return ConnectionResult.failure("Connection failed: " + e.getMessage());
        } catch (Exception e) {
            return ConnectionResult.failure("Connection failed: " + e.getMessage());
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
            return callback.execute(session);
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
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public void disconnect(String host, int port) {
        String sessionId = host + ":" + port;
        SnifferSession session = sessions.remove(sessionId);
        if (session != null) {
            session.shutdown();
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

    private String getCertificateAsPEM(X509Certificate cert) {
        if (cert == null) return null;
        try {
            byte[] certBytes = cert.getEncoded();
            String base64 = Base64.getEncoder().encodeToString(certBytes);
            return "-----BEGIN CERTIFICATE-----\n" +
                    base64.replaceAll("(.{64})", "$1\n") +
                    "\n-----END CERTIFICATE-----";
        } catch (Exception e) {
            return null;
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

            PingRequest pingRequest = PingRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .setMessage("test")
                    .build();

            stub.withDeadlineAfter(5, TimeUnit.SECONDS).ping(pingRequest);

            SnifferSession session = new SnifferSession();
            session.channel = channel;
            session.stub = stub;
            session.sessionKey = sessionKey;
            session.serverCertificate = serverCert;

            return session;

        } catch (Exception e) {
            return null;
        }
    }

    @PreDestroy
    public void shutdown() {
        sessions.values().forEach(SnifferSession::shutdown);
        sessions.clear();
    }
}