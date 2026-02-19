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

        try {
            String result = grpcClient.execute(sniffer.getHost(), sniffer.getPort(), session -> {
                PingRequest request = PingRequest.newBuilder()
                        .setSessionKey(sniffer.getSessionKey())
                        .setMessage("ping from mungos-core")
                        .build();
                return session.stub.ping(request).getMessage();
            });

            sniffer.updateLastSeen();
            snifferRepository.save(sniffer);
            return result;

        } catch (ConnectionException e) {
            SnifferRequestDTO reconnectDTO = SnifferRequestDTO.builder()
                    .host(sniffer.getHost())
                    .port(sniffer.getPort())
                    .name(sniffer.getName())
                    .location(sniffer.getLocation())
                    .build();

            if (!connect(reconnectDTO)) {
                throw new ConnectionException("Failed to reconnect to sniffer: " + id);
            }

            SnifferEntity updatedSniffer = snifferRepository.findById(id).orElseThrow();
            return grpcClient.execute(updatedSniffer.getHost(), updatedSniffer.getPort(), session -> {
                PingRequest request = PingRequest.newBuilder()
                        .setSessionKey(updatedSniffer.getSessionKey())
                        .setMessage("ping from mungos-core")
                        .build();
                return session.stub.ping(request).getMessage();
            });
        }
    }

    public StatsResponse getStats(String host, int port, String period) {
        return grpcClient.execute(host, port, session -> {
            StatsRequest request = StatsRequest.newBuilder()
                    .setSessionKey(session.sessionKey)
                    .setPeriod(period)
                    .build();
            return session.stub.getStats(request);
        });
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
        if (existingSniffer.isPresent() && !existingSniffer.get().isDeleted()){
            throw new ServiceException("Failed to create sniffer");
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
            return false;
        }

        SnifferEntity sniffer;
        if (existingSniffer.isPresent()) {
            sniffer = existingSniffer.get();
        } else {
            sniffer = SnifferEntity.builder()
                    .host(snifferDTO.getHost())
                    .port(snifferDTO.getPort())
                    .build();
        }

        sniffer.setName(snifferDTO.getName());
        sniffer.setLocation(snifferDTO.getLocation());
        sniffer.setSessionKey(result.getSessionKey());
        sniffer.setCertificate(result.getCertificate());
        sniffer.setConnected(true);
        sniffer.setDeleted(false);
        sniffer.updateLastSeen();

        snifferRepository.save(sniffer);
        return true;
    }

    public boolean checkConnection(String id) {
        return snifferRepository.findById(id)
                .map(sniffer -> grpcClient.isConnected(sniffer.getHost(), sniffer.getPort()))
                .orElse(false);
    }
}