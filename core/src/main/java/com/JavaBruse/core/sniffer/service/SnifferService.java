package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.BusyException;
import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.core.sniffer.grpc.command.PingCommand;
import com.JavaBruse.core.sniffer.grpc.command.StatsCommand;
import com.JavaBruse.core.sniffer.grpc.command.TrafficCommand;
import com.JavaBruse.core.sniffer.converters.SnifferConverter;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferRequestDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.core.sniffer.grpc.client.ConnectionResult;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.core.sniffer.grpc.retry.RetryPolicy;
import com.JavaBruse.core.sniffer.grpc.retry.RetryStrategy;
import com.JavaBruse.proto.FilterExpression;
import com.JavaBruse.proto.StatsResponse;
import com.JavaBruse.proto.TrafficPacket;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SnifferService {

    private final SnifferRepository snifferRepository;
    private final SessionManager sessionManager;
    private final PingCommand pingCommand;
    private final StatsCommand statsCommand;
    private final TrafficCommand trafficCommand;
    private final RetryPolicy retryPolicy;
    private final ConnectionValidator connectionValidator;

    public String ping(String id) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        return retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> pingCommand.execute(sniffer, null),
                this::isRetryableError,
                "ping-" + id
        );
    }

    public StatsResponse getStats(String id, String period) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        return retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> statsCommand.execute(sniffer, period),
                this::isRetryableError,
                "stats-" + id
        );
    }

    public Iterator<TrafficPacket> getFilteredTraffic(String id, FilterExpression filter, int limit, int offset) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        TrafficCommand.TrafficRequest request = TrafficCommand.TrafficRequest.builder()
                .filter(filter)
                .limit(limit)
                .offset(offset)
                .build();
        log.info("Calling gRPC for sniffer: {}", id);
        return trafficCommand.execute(sniffer, request);
    }

    public byte[] getPacketPayload(String snifferId, String packetId) {
        SnifferEntity sniffer = snifferRepository.findById(snifferId)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + snifferId));

        return trafficCommand.getPayload(sniffer, packetId);
    }

    @Transactional
    public List<SnifferResponseDTO> addSniffer(SnifferRequestDTO request) {
        validateSnifferNotExists(request);

        ConnectionResult result = establishConnection(request);
        if (!result.isSuccess()) {
            throw new ServiceException("Failed to connect to sniffer: " + result.getErrorMessage());
        }

        SnifferEntity sniffer = save(request, result);
        log.info("Successfully added sniffer: {}:{}", request.getHost(), request.getPort());
        return getAll();
    }

    @Transactional
    public List<SnifferResponseDTO> delete(String id) {
        snifferRepository.findById(id).ifPresent(this::deleteSniffer);
        return getAll();
    }

    public boolean checkConnection(String id) {
        return snifferRepository.findById(id)
                .map(connectionValidator::validateConnection)
                .orElse(false);
    }

    public List<SnifferResponseDTO> getAll() {
        return snifferRepository.findByDeletedFalse().stream()
                .map(SnifferConverter::SnifferToSnifferResponseDTO)
                .toList();
    }

    private void validateSnifferNotExists(SnifferRequestDTO request) {
        snifferRepository.findByHostAndPort(request.getHost(), request.getPort())
                .filter(sniffer -> !sniffer.isDeleted())
                .ifPresent(sniffer -> {
                    throw new ServiceException("Sniffer already exists: " +
                            request.getHost() + ":" + request.getPort());
                });
    }

    private ConnectionResult establishConnection(SnifferRequestDTO request) {
        Optional<SnifferEntity> existing = snifferRepository.findByHostAndPort(
                request.getHost(), request.getPort());
        ConnectionResult result = sessionManager.createConnection(
                request.getHost(),
                request.getPort(),
                existing.map(SnifferEntity::getSessionKey).orElse(null),
                existing.map(SnifferEntity::getCertificate).orElse(null)
        );

        if (result.isBusy()) {
            throw new BusyException("Sniffer is busy with another client");
        }

        return result;
    }

    private SnifferEntity save(SnifferRequestDTO request, ConnectionResult result) {
        SnifferEntity sniffer = snifferRepository.findByHostAndPort(request.getHost(), request.getPort())
                .orElse(SnifferEntity.builder()
                        .host(request.getHost())
                        .port(request.getPort())
                        .build());

        sniffer.setName(request.getName());
        sniffer.setLocation(request.getLocation());
        sniffer.setSessionKey(result.getSessionKey());
        sniffer.setCertificate(result.getCertificate());
        sniffer.setConnected(true);
        sniffer.setDeleted(false);
        sniffer.updateLastSeen();

        return snifferRepository.save(sniffer);
    }

    private void deleteSniffer(SnifferEntity sniffer) {
        sessionManager.invalidateSession(sniffer);
        sniffer.setDeleted(true);
        sniffer.setConnected(false);
        snifferRepository.save(sniffer);
        log.info("Deleted sniffer: {}", sniffer.getId());
    }

    private boolean isRetryableError(Exception e) {
        return e instanceof ConnectionException;
    }
}