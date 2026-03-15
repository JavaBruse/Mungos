package com.JavaBruse.core.sniffer.domain.DTO;

import com.JavaBruse.proto.TrafficPacket;
import lombok.Builder;
import lombok.Value;

import java.util.Map;

@Value
@Builder
public class TrafficPacketDTO {
    long timestamp;
    String protocol;
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

    public static TrafficPacketDTO fromProto(TrafficPacket proto) {

        return TrafficPacketDTO.builder()
                .packetId(proto.getPacketId())
                .timestamp(proto.getTimestamp())
                .protocol(proto.getProtocol())
                .srcPort(proto.getSrcPort())
                .dstPort(proto.getDstPort())
                .srcIp(proto.getSrcIp())
                .dstIp(proto.getDstIp())
                .length(proto.getLength())
                .ttl(proto.getTtl())
                .tcpFlags(proto.getTcpFlags())
                .hasPayload(!proto.getPayload().isEmpty())
                .headers(proto.getHeadersMap())
                .method(proto.getMethod())
                .uri(proto.getUri())
                .status(proto.getStatus())
                .dnsQuery(proto.getDnsQuery())
                .dnsAnswer(proto.getDnsAnswer())
                .srcMac(proto.getSrcMac())
                .dstMac(proto.getDstMac())
                .srcVendor(proto.getSrcVendor())
                .dstVendor(proto.getDstVendor())
                .ja4Raw(proto.getJa4Raw())
                .ja4Application(proto.getJa4Application())
                .ja4Device(proto.getJa4Device())
                .ja4Os(proto.getJa4Os())
                .ja4Verified(proto.getJa4Verified())
                .ja4Confidence(proto.getJa4Confidence())
                .sni(proto.getSni())
                .sniService(proto.getSniService())
                .build();
    }
}