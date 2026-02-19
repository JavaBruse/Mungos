package com.JavaBruse.core.sniffer.converters;

import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;

public class SnifferConverter {
    public static SnifferResponseDTO SnifferToSnifferResponseDTO(SnifferEntity sniffer){
        return SnifferResponseDTO.builder()
                .id(sniffer.getId())
                .name(sniffer.getName())
                .location(sniffer.getLocation())
                .host(sniffer.getHost())
                .port(sniffer.getPort())
                .lastSeen(sniffer.getLastSeen())
                .connected(sniffer.isConnected())
                .build();
    }
}
