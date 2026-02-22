package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class ConnectionValidator {

    private final SessionManager sessionManager;
    private final SnifferRepository snifferRepository;

    public boolean validateConnection(SnifferEntity sniffer) {
        try {
            boolean connected = sessionManager.isConnected(sniffer);
            updateConnectionStatus(sniffer, connected);
            return connected;
        } catch (Exception e) {
            log.debug("Connection validation failed for sniffer {}: {}", sniffer.getId(), e.getMessage());
            updateConnectionStatus(sniffer, false);
            return false;
        }
    }

    private void updateConnectionStatus(SnifferEntity sniffer, boolean connected) {
        if (sniffer.isConnected() != connected) {
            sniffer.setConnected(connected);
            snifferRepository.save(sniffer);
            log.info("Connection status updated for sniffer {}: {}", sniffer.getId(), connected);
        }
    }
}
