package com.JavaBruse.core.sniffer.domain.DTO;


import jakarta.persistence.Column;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SnifferResponseDTO {
    private String id;
    private String name;
    private String host;
    private int port;
    private String location;
    private Long lastSeen;
    private boolean connected;
    private String SNIHash;
    private String Ja4Hash;
}
