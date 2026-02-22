package com.JavaBruse.core.sniffer.controllers;

import com.JavaBruse.core.sniffer.domain.DTO.PayloadRequestDTO;
import com.JavaBruse.core.sniffer.domain.DTO.TrafficPacketDTO;
import com.JavaBruse.core.sniffer.service.SnifferService;
import com.JavaBruse.proto.FilterExpression;
import com.JavaBruse.proto.PayloadRequest;
import com.JavaBruse.proto.TrafficPacket;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.util.Iterator;
import java.util.List;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SnifferWebSocketController {

    private final SnifferService snifferService;
    private final SimpMessagingTemplate messagingTemplate;

    @MessageMapping("/traffic.request")
    public void requestTraffic(@Payload TrafficRequest request) {
        String destination = "/api/v1/topic/traffic/" + request.snifferId;
        try {
            FilterExpression filter = FilterExpression.newBuilder()
                    .addAllProtocols(request.protocols != null ? request.protocols : List.of())
                    .addAllPorts(request.ports != null ? request.ports : List.of())
                    .addAllIps(request.ips != null ? request.ips : List.of())
                    .setStartTime(request.startTime != null ? request.startTime : 0)
                    .setEndTime(request.endTime != null ? request.endTime : 0)
                    .setTextSearch(request.textSearch != null ? request.textSearch : "")
                    .build();

            Iterator<TrafficPacket> packets = snifferService.getFilteredTraffic(
                    request.snifferId,
                    filter,
                    request.limit,
                    request.offset
            );

            int count = 0;
            while (packets.hasNext()) {
                TrafficPacket protoPacket = packets.next();
                TrafficPacketDTO dto = TrafficPacketDTO.fromProto(protoPacket);
                messagingTemplate.convertAndSend(destination + "/packet", dto);
                count++;
            }

            messagingTemplate.convertAndSend(destination + "/complete",
                    new CompletionMessage(count));

        } catch (Exception e) {
            log.error("Traffic stream error: {}", e.getMessage());
            messagingTemplate.convertAndSend(destination + "/error",
                    new ErrorMessage(e.getMessage()));
        }
    }

    @MessageMapping("/traffic.payload")
    public void requestPayload(@Payload PayloadRequestDTO request) {
        String destination = "/api/v1/topic/payload/" + request.getPacketId();
        log.info("Received payload request: {}", request);

        try {
            byte[] payload = snifferService.getPacketPayload(
                    request.getSnifferId(),
                    request.getPacketId()
            );
            log.info("Sending payload for packet: {}, size: {} bytes",
                    request.getPacketId(), payload.length);  // ← добавить
            messagingTemplate.convertAndSend(destination, payload);

        } catch (Exception e) {
            log.error("Payload request error: {}", e.getMessage());
            messagingTemplate.convertAndSend(destination + "/error", e.getMessage());
        }
    }

    public record TrafficRequest(
            String snifferId,
            List<String> protocols,
            List<Integer> ports,
            List<String> ips,
            Long startTime,
            Long endTime,
            String textSearch,
            int limit,
            int offset
    ) {}

    public record CompletionMessage(int totalPackets) {}
    public record ErrorMessage(String error) {}
}