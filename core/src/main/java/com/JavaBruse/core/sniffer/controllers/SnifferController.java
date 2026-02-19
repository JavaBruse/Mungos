package com.JavaBruse.core.sniffer.controllers;


import com.JavaBruse.core.exaption.BusyException;
import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.exaption.ServiceException;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferRequestDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
import com.JavaBruse.core.sniffer.service.SnifferService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/sniffer")
@RequiredArgsConstructor
public class SnifferController {

    private final SnifferService snifferService;

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> signUp(@RequestBody @Valid SnifferRequestDTO request) {
        try{
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

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void deleteSniffer (@PathVariable String id) {
        snifferService.delete(id);
    }

    @GetMapping("/ping/{id}")
    public ResponseEntity<String> ping(@PathVariable String id) {
        try {
            String result = snifferService.ping(id);
            return ResponseEntity.ok(result);

        } catch (BusyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("ERROR: " + e.getMessage());

        } catch (ConnectionException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("ERROR: " + e.getMessage());

        } catch (ServiceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("ERROR: " + e.getMessage());
        }
    }
}
