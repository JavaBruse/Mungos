package com.JavaBruse.core.sniffer;

import com.JavaBruse.proto.*;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class SnifferGrpcClient {

    @Value("${sniffer.host}")
    private String snifferHost;

    @Value("${sniffer.port}")
    private int snifferPort;

    @Value("${sniffer.master-key}")
    private String masterKey;

    private ManagedChannel channel;
    private SnifferServiceGrpc.SnifferServiceBlockingStub stub;
    private String sessionKey;

    @PostConstruct
    public void init() {
        log.info("Connecting to sniffer at {}:{}", snifferHost, snifferPort);

        // Создаем канал (без шифрования для теста)
        channel = ManagedChannelBuilder.forAddress(snifferHost, snifferPort)
                .usePlaintext()  // Только для теста! В проде TLS
                .build();

        stub = SnifferServiceGrpc.newBlockingStub(channel);

        // Регистрируемся при старте
        registerWithSniffer();
    }


    private void registerWithSniffer() {
        try {
            RegisterRequest request = RegisterRequest.newBuilder()
                    .setMasterKey(masterKey)
                    .setSnifferId("java-server-" + System.currentTimeMillis())
                    .build();

            RegisterResponse response = stub.register(request);

            if (response.getSuccess()) {
                this.sessionKey = response.getSessionKey();
                log.info("Registered with sniffer. Session key: {}", sessionKey);
                log.info("Message: {}", response.getMessage());
            } else {
                log.error("Registration failed: {}", response.getMessage());
            }

        } catch (Exception e) {
            log.error("Failed to register with sniffer", e);
        }
    }

    public String ping() {
        try {
            PingRequest request = PingRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .setMessage("ping from Java")
                    .build();

            PingResponse response = stub.withDeadlineAfter(5, TimeUnit.SECONDS)
                    .ping(request);

            log.info("Pong from sniffer: {} at {}",
                    response.getMessage(), response.getTimestamp());

            return response.getMessage();

        } catch (Exception e) {
            log.error("Ping failed", e);
            return "ERROR: " + e.getMessage();
        }
    }

    public StatsResponse getStats(String period) {
        try {
            StatsRequest request = StatsRequest.newBuilder()
                    .setSessionKey(sessionKey)
                    .setPeriod(period)
                    .build();

            StatsResponse response = stub.getStats(request);

            if (response.getError().isEmpty()) {
                log.info("Stats: packets={}, bytes={}",
                        response.getPacketsCount(), response.getBytesTotal());
                return response;
            } else {
                log.error("Stats error: {}", response.getError());
                return null;
            }

        } catch (Exception e) {
            log.error("Get stats failed", e);
            return null;
        }
    }


    public void shutdown() {
        if (channel != null) {
            channel.shutdown();
        }
    }
}