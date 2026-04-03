package com.JavaBruse.core.security.repository;

import com.JavaBruse.core.security.domain.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {
    Page<AuditLog> findAll(Pageable pageable);
    Page<AuditLog> findByUserNameContainingIgnoreCaseOrActionContainingIgnoreCase(
            String userName, String action, Pageable pageable);
}
