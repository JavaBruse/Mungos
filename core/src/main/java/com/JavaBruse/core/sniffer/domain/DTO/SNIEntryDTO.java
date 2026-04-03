package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SNIEntryDTO {
    private String id;
    private String service;
    private String sni;
    private int occurrenceCount;
    private long firstSeen;
    private long lastSeen;
    private String sessionKey;
}