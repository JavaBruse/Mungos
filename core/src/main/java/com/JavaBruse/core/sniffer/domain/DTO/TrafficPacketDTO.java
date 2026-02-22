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
                .hasPayload(proto.getPayload() != null && proto.getPayload().size() > 0)
                .headers(proto.getHeadersMap())
                .method(proto.getMethod())
                .uri(proto.getUri())
                .status(proto.getStatus())
                .dnsQuery(proto.getDnsQuery())
                .dnsAnswer(proto.getDnsAnswer())
                .packetId(proto.getPacketId())
                .build();
    }
}