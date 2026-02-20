package com.JavaBruse.core.sniffer.controllers;

import com.JavaBruse.core.sniffer.service.SnifferService;
import com.JavaBruse.proto.StatsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SnifferWebSocketController {

    private final SnifferService snifferService;
    private final SimpMessagingTemplate messagingTemplate;

    @MessageMapping("/api/v1/traffic.request")
    public void requestTraffic(@Payload TrafficRequest request) {
        String destination = "/api/v1/topic/traffic/" + request.snifferId;

        // Обычный gRPC запрос в Go
        StatsResponse response = snifferService.getStats(
                request.snifferId,
                request.period
        );

        // Отправляем результат во фронт
        messagingTemplate.convertAndSend(destination, response);
    }

    record TrafficRequest(String snifferId, String period) {}
}