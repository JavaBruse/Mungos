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
    private Long identifiedPackets;
    private List<JA4CandidateDTO> ja4Candidates;
    private List<SNICandidateDTO> sniCandidates;

    @Data
    public static class JA4CandidateDTO {
        private String id;
        private String fingerprint;
        private String application;
        private String device;
        private String os;
        private Long count;
        private Integer confidence;
        private Integer hop;
    }

    @Data
    public static class SNICandidateDTO {
        private String id;
        private String sni;
        private String service;
        private Long count;
        private Integer confidence;
        private Integer hop;
    }
}