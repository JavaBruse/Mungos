package com.JavaBruse.core.security.controllers;

import com.JavaBruse.core.security.service.AuditLogService;
import com.JavaBruse.core.security.domain.model.AuditLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@Slf4j
@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditLogController {
    private final AuditLogService auditLogService;

//    @GetMapping("/all")
//    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
//    public Page<AuditLog> getAll(@RequestParam(defaultValue = "0") int page,
//                                 @RequestParam(defaultValue = "100") int size) {
//        return auditLogService.getAll(page, size);
//    }

    @GetMapping("/all")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public Page<AuditLog> getAll(@RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "100") int size,
                                 @RequestParam(required = false) String userName) {
        return auditLogService.getAll(page, size, userName);
    }
}
