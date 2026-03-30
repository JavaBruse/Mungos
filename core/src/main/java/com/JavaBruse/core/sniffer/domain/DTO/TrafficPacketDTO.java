package com.JavaBruse.core.sniffer.domain.DTO;

import lombok.Builder;
import lombok.Value;

import java.util.List;
import java.util.Map;

@Value
@Builder
public class TrafficPacketDTO {
    long timestamp;
    List<String> protocols;
    int srcPort;
    int dstPort;
    String srcIp;
    String dstIp;
    int length;
    boolean hasPayload;
    Map<String, String> headers;
    String method;
    String uri;
    int status;
    String dnsQuery;
    String dnsAnswer;
    String packetId;
    int ttl;
    String tcpFlags;
    String srcMac;
    String dstMac;
    String srcVendor;
    String dstVendor;
    String ja4Raw;
    String ja4Application;
    String ja4Device;
    String ja4Os;
    boolean ja4Verified;
    int ja4Confidence;
    String sni;
    String sniService;
    String srcIpType;
    String dstIpType;
}