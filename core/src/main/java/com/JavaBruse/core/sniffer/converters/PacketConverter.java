package com.JavaBruse.core.sniffer.converters;


import com.JavaBruse.core.sniffer.domain.DTO.TrafficPacketDTO;
import com.JavaBruse.proto.TrafficPacket;
import org.springframework.stereotype.Component;

@Component
public class PacketConverter {
    public static TrafficPacketDTO fromProto(TrafficPacket proto) {
        String srcIp = proto.getSrcIp();
        String dstIp = proto.getDstIp();
        String srcMac = proto.getSrcMac();
        String dstMac = proto.getDstMac();

        if ("private".equals(proto.getSrcIpType()) && srcIp != null && !srcIp.isEmpty()) {
            srcIp = maskIp(srcIp);
        }
        if ("private".equals(proto.getDstIpType()) && dstIp != null && !dstIp.isEmpty()) {
            dstIp = maskIp(dstIp);
        }

        if (srcMac != null && !srcMac.isEmpty()) {
            srcMac = maskMac(srcMac);
        }
        if (dstMac != null && !dstMac.isEmpty()) {
            dstMac = maskMac(dstMac);
        }

        return TrafficPacketDTO.builder()
                .packetId(proto.getPacketId())
                .timestamp(proto.getTimestamp())
                .protocols(proto.getProtocolStackList())
                .srcPort(proto.getSrcPort())
                .dstPort(proto.getDstPort())
                .srcIp(srcIp)
                .dstIp(dstIp)
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
                .srcMac(srcMac)
                .dstMac(dstMac)
                .srcVendor(proto.getSrcVendor())
                .dstVendor(proto.getDstVendor())
                .ja4Raw(proto.getJa4Raw())
                .ja4Type(proto.getJa4Type())
                .ja4Application(proto.getJa4Application())
                .ja4Device(proto.getJa4Device())
                .ja4Os(proto.getJa4Os())
                .ja4Verified(proto.getJa4Verified())
                .ja4Confidence(proto.getJa4Confidence())
                .sni(proto.getSni())
                .sniService(proto.getSniService())
                .srcIpType(proto.getSrcIpType())
                .dstIpType(proto.getDstIpType())
                .build();
    }

    private static String maskIp(String ip) {
        if (ip == null || ip.isEmpty()) return ip;
        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".***";
            }
        }
        if (ip.contains(":")) {
            String[] parts = ip.split(":");
            if (parts.length >= 4) {
                StringBuilder masked = new StringBuilder();
                for (int i = 0; i < parts.length - 2; i++) {
                    if (i > 0) masked.append(":");
                    masked.append(parts[i]);
                }
                masked.append(":**:**");
                return masked.toString();
            }
        }
        return ip;
    }

    private static String maskMac(String mac) {
        if (mac == null || mac.isEmpty()) return mac;
        String[] parts = mac.split(":");
        if (parts.length == 6) {
            return parts[0] + ":" + parts[1] + ":" + parts[2] + ":**:**:**";
        }
        parts = mac.split("-");
        if (parts.length == 6) {
            return parts[0] + "-" + parts[1] + "-" + parts[2] + "-**-**-**";
        }
        return mac;
    }
}
