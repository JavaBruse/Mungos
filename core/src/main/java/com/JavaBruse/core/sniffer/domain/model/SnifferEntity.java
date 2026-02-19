package com.JavaBruse.core.sniffer.domain.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "sniffers")
public class SnifferEntity {
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "name", unique = true, nullable = false)
    private String name;

    @Column(name = "host", nullable = false)
    private String host;

    @Column(name = "port", nullable = false)
    private int port;

    @Column(name = "session_key")
    private String sessionKey;

    @Column(name = "certificate", length = 4096)
    private String certificate;

    @Column(name = "last_seen")
    private Long lastSeen;

    @Column(name = "connected")
    private boolean connected;

    @Column(name = "location")
    private String location;

    @Column(name = "deleted")
    private boolean deleted = false;

    public void updateLastSeen() {
        this.lastSeen = Instant.now().getEpochSecond();
    }
}
