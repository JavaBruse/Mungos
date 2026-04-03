package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JA4EntryDTO {
    private String id;
    private String fingerprint;
    private String application;
    private String library;
    private String device;
    private String os;
    private int observationCount;
    private boolean verified;
    private String fingerprintType;
    private String sessionKey;
    private long updatedAt;
}
