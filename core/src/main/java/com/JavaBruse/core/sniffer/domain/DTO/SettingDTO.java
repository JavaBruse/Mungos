package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SettingDTO {
    String id;
    String filters;
    Long date;
}
