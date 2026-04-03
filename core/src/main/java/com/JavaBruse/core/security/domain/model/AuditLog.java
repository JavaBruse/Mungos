package com.JavaBruse.core.security.domain.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "audit_log")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String userId;
    private String userName;

    @Column(nullable = false)
    private String action;

    private String target;

    @Column(length = 1024)
    private String details;

    private String ipAddress;

    @Column(nullable = false)
    private Long timestamp;
}