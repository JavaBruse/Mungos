package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.Data;

@Data
public class PayloadRequestDTO {
    private String snifferId;
    private String packetId;
}