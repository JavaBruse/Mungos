package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SnifferRequestDTO {
    private String id;
    private String name;
    private String location;
    private String host;
    private int port;
}
