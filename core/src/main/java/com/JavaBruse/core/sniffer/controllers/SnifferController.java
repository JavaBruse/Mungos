package com.JavaBruse.core.sniffer.controllers;


import com.JavaBruse.core.security.domain.model.AuditAction;
import com.JavaBruse.core.security.service.AuditLogService;
import com.JavaBruse.core.exaption.BusyException;
import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.core.sniffer.domain.DTO.*;
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
    private final AuditLogService auditLogService;

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> create(@RequestBody SnifferRequestDTO request) {
        try {
            snifferService.addSniffer(request);
            auditLogService.log(AuditAction.ADD_SNIFFER);
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
            auditLogService.log(AuditAction.UPDATE_SNIFFER_SETTINGS);
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

    @PostMapping("/insight/{id}/{packetId}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYTIC', 'ROLE_SECURITY')")
    public void updateConnectionInsight(
            @PathVariable String id,
            @PathVariable String packetId,
            @RequestBody UpdateInsightRequestDTO request) {
        auditLogService.log(AuditAction.UPDATE_INSIGHT, null, "packetId="+ packetId, "ja4EntryId=" + request.getJa4EntryId() + ", sniEntryId=" + request.getSniEntryId());
        snifferService.updateConnectionInsight(id, packetId, request.getJa4EntryId(), request.getSniEntryId());
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void deleteSniffer(@PathVariable String id) {
        auditLogService.log(AuditAction.DELETE_SNIFFER);
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
        auditLogService.log(AuditAction.SYNC_JA4);
        databaseService.syncJA4Databases();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/sni/sync")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> syncSNIDatabases() {
        auditLogService.log(AuditAction.SYNC_SNI);
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
