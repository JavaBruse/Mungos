package com.JavaBruse.core.sniffer.controllers;

import com.JavaBruse.core.sniffer.service.MetricsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/metrics")
@RequiredArgsConstructor
public class SnifferMetricsController {

    private final MetricsService metricsService;

    @GetMapping(value = "/sniffer/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getPrometheusMetrics(@PathVariable UUID id) {
        return metricsService.getMetricsInPrometheusFormat(id);
    }

    @GetMapping(value = "/sniffers", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> getClients() {
        return metricsService.getClients();
    }
}