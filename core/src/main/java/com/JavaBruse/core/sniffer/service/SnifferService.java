package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.BusyException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.core.sniffer.converters.SnifferConverter;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferRequestDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.proto.PingRequest;
import com.JavaBruse.proto.StatsRequest;
import com.JavaBruse.proto.StatsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SnifferService {

    private final SnifferRepository snifferRepository;
    private final SnifferGrpcClient grpcClient;

    public String ping(String id) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found with id: " + id));

        int maxRetries = 2;
        int retryCount = 0;

        while (retryCount < maxRetries) {
            try {
                String result = grpcClient.execute(sniffer.getHost(), sniffer.getPort(), session -> {
                    PingRequest request = PingRequest.newBuilder()
                            .setSessionKey(session.sessionKey)
                            .setMessage("ping from mungos-core")
                            .build();
                    return session.stub.ping(request).getMessage();
                });

                // Обновляем время последнего контакта
                sniffer.updateLastSeen();
                sniffer.setConnected(true);
                snifferRepository.save(sniffer);

                log.info("Ping successful for sniffer: {}", sniffer.getId());
                return result;

            } catch (ConnectionException e) {
                retryCount++;
                if (retryCount >= maxRetries) {
                    log.error("Ping failed after {} retries for sniffer {}", retryCount, id);
                    sniffer.setConnected(false);
                    snifferRepository.save(sniffer);
                    throw new ConnectionException("Failed to ping sniffer after retries: " + e.getMessage());
                }

                log.info("Connection lost, attempt {}/{} to reconnect...", retryCount, maxRetries);

                // Пытаемся переподключиться
                boolean reconnected = reconnect(sniffer);

                if (!reconnected) {
                    log.error("Reconnection attempt {}/{} failed", retryCount, maxRetries);
                    // Небольшая пауза перед следующей попыткой
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new ConnectionException("Interrupted during reconnect");
                    }
                }
            }
        }

        throw new ConnectionException("Failed to ping sniffer after " + maxRetries + " attempts");
    }

    private String executePing(SnifferEntity sniffer) {
        try {
            String result = grpcClient.execute(sniffer.getHost(), sniffer.getPort(), session -> {
                PingRequest request = PingRequest.newBuilder()
                        .setSessionKey(session.sessionKey)
                        .setMessage("ping from mungos-core")
                        .build();
                return session.stub.ping(request).getMessage();
            });

            // Обновляем время последнего контакта
            sniffer.updateLastSeen();
            sniffer.setConnected(true);
            snifferRepository.save(sniffer);

            log.info("Ping successful for sniffer: {}", sniffer.getId());
            return result;

        } catch (Exception e) {
            log.error("Ping execution failed: {}", e.getMessage());
            throw new ConnectionException("Failed to execute ping: " + e.getMessage());
        }
    }

    private boolean reconnect(SnifferEntity sniffer) {
        log.info("Reconnecting to sniffer {}:{}", sniffer.getHost(), sniffer.getPort());

        SnifferRequestDTO reconnectDTO = SnifferRequestDTO.builder()
                .host(sniffer.getHost())
                .port(sniffer.getPort())
                .name(sniffer.getName())
                .location(sniffer.getLocation())
                .build();

        try {
            SnifferGrpcClient.ConnectionResult result = grpcClient.connect(
                    sniffer.getHost(),
                    sniffer.getPort(),
                    sniffer.getSessionKey(),
                    sniffer.getCertificate()
            );

            if (result.isSuccess()) {
                // Обновляем данные в БД
                sniffer.setSessionKey(result.getSessionKey());
                if (result.getCertificate() != null) {
                    sniffer.setCertificate(result.getCertificate());
                }
                sniffer.setConnected(true);
                sniffer.updateLastSeen();
                snifferRepository.save(sniffer);

                log.info("Successfully reconnected to sniffer: {}", sniffer.getId());
                return true;
            } else if (result.isBusy()) {
                log.error("Sniffer is busy with another client: {}", sniffer.getId());
                sniffer.setConnected(false);
                snifferRepository.save(sniffer);
                return false;
            } else {
                log.error("Failed to reconnect: {}", result.getErrorMessage());
                sniffer.setConnected(false);
                snifferRepository.save(sniffer);
                return false;
            }
        } catch (Exception e) {
            log.error("Reconnection error: {}", e.getMessage());
            sniffer.setConnected(false);
            snifferRepository.save(sniffer);
            return false;
        }
    }

    public StatsResponse getStats(String id, String period) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found with id: " + id));

        try {
            StatsResponse response = executeGetStats(sniffer, period);
            return response;
        } catch (ConnectionException e) {
            log.info("Connection lost for sniffer {}, attempting to reconnect...", id);

            boolean reconnected = reconnect(sniffer);

            if (reconnected) {
                sniffer = snifferRepository.findById(id)
                        .orElseThrow(() -> new ConnectionException("Sniffer not found after reconnect"));
                return executeGetStats(sniffer, period);
            } else {
                throw new ServiceException("Failed to get stats: " + e.getMessage());
            }
        }
    }

    private StatsResponse executeGetStats(SnifferEntity sniffer, String period) {
        try {
            StatsResponse response = grpcClient.execute(sniffer.getHost(), sniffer.getPort(), session -> {
                StatsRequest request = StatsRequest.newBuilder()
                        .setSessionKey(session.sessionKey)
                        .setPeriod(period)
                        .build();
                return session.stub.getStats(request);
            });

            sniffer.updateLastSeen();
            sniffer.setConnected(true);
            snifferRepository.save(sniffer);

            return response;

        } catch (Exception e) {
            sniffer.setConnected(false);
            snifferRepository.save(sniffer);
            throw new ConnectionException("Failed to execute getStats: " + e.getMessage());
        }
    }

    public List<SnifferResponseDTO> getAll() {
        return snifferRepository.findAll().stream()
                .filter(x -> !x.isDeleted())
                .map(SnifferConverter::SnifferToSnifferResponseDTO)
                .toList();
    }

    @Transactional
    public List<SnifferResponseDTO> addSniffer(SnifferRequestDTO snifferDTO) {
        Optional<SnifferEntity> existingSniffer = snifferRepository.findByHostAndPort(
                snifferDTO.getHost(), snifferDTO.getPort()
        );

        if (existingSniffer.isPresent() && !existingSniffer.get().isDeleted()) {
            throw new ServiceException("Sniffer already exists with host: " + snifferDTO.getHost() + " and port: " + snifferDTO.getPort());
        }

        if (!connect(snifferDTO)) {
            throw new ServiceException("Failed to connect to sniffer");
        }

        return getAll();
    }

    @Transactional
    public List<SnifferResponseDTO> delete(String id) {
        Optional<SnifferEntity> sniffer = snifferRepository.findById(id);
        if (sniffer.isPresent()) {
            SnifferEntity snifferEntity = sniffer.get();
            grpcClient.disconnect(snifferEntity.getHost(), snifferEntity.getPort());
            snifferEntity.setDeleted(true);
            snifferEntity.setConnected(false);
            snifferRepository.save(snifferEntity);
            log.info("Deleted sniffer: {}", id);
        }
        return getAll();
    }

    @Transactional
    public boolean connect(SnifferRequestDTO snifferDTO) {
        Optional<SnifferEntity> existingSniffer = snifferRepository.findByHostAndPort(
                snifferDTO.getHost(), snifferDTO.getPort()
        );

        SnifferGrpcClient.ConnectionResult result = grpcClient.connect(
                snifferDTO.getHost(),
                snifferDTO.getPort(),
                existingSniffer.map(SnifferEntity::getSessionKey).orElse(null),
                existingSniffer.map(SnifferEntity::getCertificate).orElse(null)
        );

        if (result.isBusy()) {
            throw new BusyException("Sniffer is busy with another client");
        }

        if (!result.isSuccess()) {
            log.error("Failed to connect to sniffer: {}", result.getErrorMessage());
            return false;
        }

        SnifferEntity sniffer;
        if (existingSniffer.isPresent()) {
            sniffer = existingSniffer.get();
            log.info("Updating existing sniffer: {}", snifferDTO.getHost());
        } else {
            sniffer = SnifferEntity.builder()
                    .host(snifferDTO.getHost())
                    .port(snifferDTO.getPort())
                    .build();
            log.info("Creating new sniffer: {}", snifferDTO.getHost());
        }

        sniffer.setName(snifferDTO.getName());
        sniffer.setLocation(snifferDTO.getLocation());
        sniffer.setSessionKey(result.getSessionKey());

        if (result.getCertificate() != null) {
            sniffer.setCertificate(result.getCertificate());
        }

        sniffer.setConnected(true);
        sniffer.setDeleted(false);
        sniffer.updateLastSeen();

        snifferRepository.save(sniffer);
        log.info("Successfully connected to sniffer: {}:{}", snifferDTO.getHost(), snifferDTO.getPort());
        return true;
    }

    public boolean checkConnection(String id) {
        return snifferRepository.findById(id)
                .map(sniffer -> {
                    boolean connected = grpcClient.isConnected(sniffer.getHost(), sniffer.getPort());
                    if (connected != sniffer.isConnected()) {
                        sniffer.setConnected(connected);
                        snifferRepository.save(sniffer);
                    }
                    return connected;
                })
                .orElse(false);
    }
}