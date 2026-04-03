package com.JavaBruse.core.security.service;

import com.JavaBruse.core.security.domain.model.AuditAction;
import com.JavaBruse.core.security.domain.model.AuditLog;
import com.JavaBruse.core.security.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
@RequiredArgsConstructor
public class AuditLogService {
    private final AuditLogRepository auditLogRepository;
    private final UserService userService;

    public void log(AuditAction action) {
        log(action, null, null, null);
    }

    public void log(AuditAction action, String target) {
        log(action, null, target, null);
    }

    public void log(AuditAction action, String username, String target, String details) {
        String userId = null;
        if (username == null) {
            username = getCurrentUserName();
        }
        if (username != null) {
            try {
                userId = userService.getByUsername(username).getId();
            } catch (Exception e) {
            }
        }

        String ip = getClientIp();
        AuditLog log = AuditLog.builder()
                .userId(userId)
                .userName(username)
                .action(action.getValue())
                .target(target)
                .details(details)
                .ipAddress(ip)
                .timestamp(System.currentTimeMillis())
                .build();
        auditLogRepository.save(log);
    }

    private String getCurrentUserName() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : null;
    }

    private String getClientIp() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest().getRemoteAddr() : null;
    }

    public Page<AuditLog> getAll(int page, int size, String query) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp"));
        if (query != null && !query.isEmpty()) {
            return auditLogRepository.findByUserNameContainingIgnoreCaseOrActionContainingIgnoreCase(query, query, pageable);
        }
        return auditLogRepository.findAll(pageable);
    }
}