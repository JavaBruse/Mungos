package com.JavaBruse.core.sniffer.controllers;


import com.JavaBruse.core.exaption.BusyException;
import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.core.sniffer.domain.DTO.ConnectionInsightDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SettingDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferRequestDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
import com.JavaBruse.core.sniffer.service.DataBaseJa4SNIService;
import com.JavaBruse.core.sniffer.service.SnifferService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/v1/sniffer")
@RequiredArgsConstructor
public class SnifferController {

    private final SnifferService snifferService;
    private final DataBaseJa4SNIService databaseService;

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> create(@RequestBody SnifferRequestDTO request) {
        try {
            snifferService.addSniffer(request);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (ServiceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/all")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYTIC', 'ROLE_SECURITY')")
    public List<SnifferResponseDTO> getAll() {
        return snifferService.getAll();
    }

    @PostMapping("/setting")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> saveSetting(@RequestBody SettingDTO request) {
        try {
            snifferService.setSettings(request);
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (ServiceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/setting/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public SettingDTO getSetting(@PathVariable String id) {
        return snifferService.getSettings(id);
    }

    @GetMapping("/insight/{id}/{packetId}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYTIC', 'ROLE_SECURITY')")
    public ConnectionInsightDTO getConnectionInsight(@PathVariable String id, @PathVariable String packetId) {
        return snifferService.getConnectionInsight(id, packetId);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void deleteSniffer(@PathVariable String id) {
        snifferService.delete(id);
    }

    @GetMapping("/ping/{id}")
    public ResponseEntity<Void> ping(@PathVariable String id) {
        try {
            snifferService.ping(id);
            return ResponseEntity.ok().build();
        } catch (BusyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        } catch (ConnectionException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        } catch (ServiceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/ja4/sync")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> syncJA4Databases() {
        log.info("POST sync all JA4 databases");
        databaseService.syncJA4Databases();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/sni/sync")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> syncSNIDatabases() {
        log.info("POST sync all SNI databases");
        databaseService.syncSNIDatabases();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/hashes/update-all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> updateAllSnifferHashes() {
        snifferService.updateHashSNIAndJa4AllSniffer();
        return ResponseEntity.ok().build();
    }
}
