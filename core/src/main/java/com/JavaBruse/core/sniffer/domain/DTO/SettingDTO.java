package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.*;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SettingDTO {
    String id;
    List<String> filters;
    Long date;
}
