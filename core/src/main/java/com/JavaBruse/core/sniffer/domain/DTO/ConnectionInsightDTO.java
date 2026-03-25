package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.Data;

import java.util.List;

@Data
public class ConnectionInsightDTO {
    private String localIp;
    private List<Integer> localPorts;
    private String remoteIp;
    private Integer remotePort;
    private Long totalPackets;
    private Long totalBytes;
    private Long firstPacketTime;
    private Long lastPacketTime;
    private Long synCount;
    private Long finCount;
    private Long rstCount;
    private List<IdentificDataDTO> identificData;

    @Data
    public static class IdentificDataDTO {
        private List<String> uniqueJa4Raw;
        private List<String> uniqueJa4Application;
        private List<String> uniqueJa4Device;
        private List<String> uniqueJa4Os;
        private List<String> uniqueSni;
        private List<String> uniqueSniService;
        private List<String> uniqueJa4EntryId;
        private List<String> uniqueSniEntryId;
        private List<RelatedAddressDTO> relatedAddressJa4;
        private List<RelatedAddressDTO> relatedAddressSni;
        @Data
       public static class RelatedAddressDTO {
            private String remoteIp;
            private Integer remotePort;
            private Long count;
        }

    }
}