package com.JavaBruse.core.sniffer.grpc.client;

import com.JavaBruse.core.exaption.ConnectionException;
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
import org.springframework.stereotype.Component;

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
@Component
public class GrpcConnectionManager {

    @Value("${sniffer.master-key}")
    private String masterKey;

    private final ConcurrentHashMap<String, ManagedChannel> channels = new ConcurrentHashMap<>();

    public ConnectionResult connect(String host, int port, String existingSessionKey, String existingCertPEM) {
        String connectionId = buildConnectionId(host, port);


        if (existingSessionKey != null) {
            ConnectionResult renewalResult = tryRenewSession(host, port, existingSessionKey, connectionId);
            if (renewalResult.isSuccess()) {
                return renewalResult;
            }
        }

        return registerNewClient(host, port, connectionId);
    }

    private ConnectionResult tryRenewSession(String host, int port, String sessionKey, String connectionId) {
        ManagedChannel insecureChannel = null;
        try {
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            insecureChannel = createChannel(host, port, insecureSslContext);
            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub =
                    SnifferServiceGrpc.newBlockingStub(insecureChannel);

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

//            closeChannel(insecureChannel);
//            Thread.sleep(100);

            ManagedChannel secureChannel = createSecureChannel(host, port, newCertPEM);
            if (secureChannel != null) {
                channels.put(connectionId, secureChannel);
                return ConnectionResult.success(newSessionKey, newCertPEM);
            }

            return ConnectionResult.failure("Failed to create secure channel");

        } catch (Exception e) {
            log.error("Session renewal error: {}", e.getMessage());
            return ConnectionResult.failure("Session renewal failed: " + e.getMessage());
        } finally {
            closeChannel(insecureChannel);
        }
    }

    private ConnectionResult registerNewClient(String host, int port, String connectionId) {
        ManagedChannel insecureChannel = null;
        try {
            SslContext insecureSslContext = GrpcSslContexts.forClient()
                    .trustManager(io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();

            insecureChannel = createChannel(host, port, insecureSslContext);
            SnifferServiceGrpc.SnifferServiceBlockingStub insecureStub =
                    SnifferServiceGrpc.newBlockingStub(insecureChannel);

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

//            closeChannel(insecureChannel);
//            Thread.sleep(100);

            ManagedChannel secureChannel = createSecureChannel(host, port, certPEM);
            if (secureChannel != null) {
                channels.put(connectionId, secureChannel);
                return ConnectionResult.success(sessionKey, certPEM);
            }

            return ConnectionResult.failure("Failed to create secure channel");

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
            closeChannel(insecureChannel);
        }
    }

    public SnifferServiceGrpc.SnifferServiceBlockingStub getStub(String host, int port) {
        String connectionId = buildConnectionId(host, port);
        ManagedChannel channel = channels.get(connectionId);

        if (channel == null) {
            throw new ConnectionException("No active channel for " + connectionId);
        }

        return SnifferServiceGrpc.newBlockingStub(channel);
    }

    public boolean isConnected(String host, int port) {
        String connectionId = buildConnectionId(host, port);
        return channels.containsKey(connectionId);
    }

    public void disconnect(String host, int port) {
        String connectionId = buildConnectionId(host, port);
        ManagedChannel channel = channels.remove(connectionId);

        if (channel != null) {
            closeChannel(channel);
            log.info("Disconnected from {}", connectionId);
        }
    }

    private ManagedChannel createChannel(String host, int port, SslContext sslContext) {
        return NettyChannelBuilder.forAddress(host, port)
                .sslContext(sslContext)
                .overrideAuthority("sniffer-server")
                .build();
    }

    private ManagedChannel createSecureChannel(String host, int port, String certPEM) {
        ManagedChannel channel = null;
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

            channel = createChannel(host, port, sslContext);
            return channel;

        } catch (Exception e) {
            if (channel != null) {
                closeChannel(channel);
            }
            log.error("Failed to create secure channel: {}", e.getMessage());
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


    private String buildConnectionId(String host, int port) {
        return host + ":" + port;
    }

    private void closeChannel(ManagedChannel channel) {
        if (channel != null && !channel.isShutdown()) {
            channel.shutdown();
        }
    }

    @PreDestroy
    public void shutdown() {
        channels.values().forEach(this::closeChannel);
        channels.clear();
    }
}