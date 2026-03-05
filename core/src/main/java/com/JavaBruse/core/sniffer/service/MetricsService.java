package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.proto.MetricsResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class MetricsService {
    private final SnifferRepository snifferRepository;
    private final SnifferService snifferService;

    @Value("${server.port}")
    private String port;

    public List<Map<String, Object>> getClients() {
        List<SnifferEntity> sniffers = snifferRepository.findAll();
        List<Map<String, Object>> result = new ArrayList<>();
        String baseTarget = "core-app:" + port;
        for (SnifferEntity s : sniffers) {
            Map<String, Object> client = new HashMap<>();
            client.put("targets", Collections.singletonList(baseTarget));
            Map<String, String> labels = new HashMap<>();
            labels.put("instance", s.getName());
            labels.put("id", s.getId().toString());
            labels.put("__metrics_path__", "/metrics/sniffer/" + s.getId());
            client.put("labels", labels);
            result.add(client);
        }
        return result;
    }

    public String getMetricsInPrometheusFormat(UUID uuid) {
        SnifferEntity sniffer = snifferRepository.findById(uuid.toString())
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + uuid));

        MetricsResponse metrics = snifferService.getMetrics(sniffer.getId());

        StringBuilder sb = new StringBuilder();

        // Основные счетчики
        sb.append("# HELP sniffer_packets_total Total packets captured\n");
        sb.append("# TYPE sniffer_packets_total counter\n");
        sb.append(String.format("sniffer_packets_total{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getPacketsCount()));

        sb.append("# HELP sniffer_bytes_total Total bytes captured\n");
        sb.append("# TYPE sniffer_bytes_total counter\n");
        sb.append(String.format("sniffer_bytes_total{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getBytesTotal()));

        // Протоколы
        if (metrics.getProtocolsMap() != null) {
            for (Map.Entry<String, Long> entry : metrics.getProtocolsMap().entrySet()) {
                sb.append(String.format("sniffer_protocol_packets{sniffer=\"%s\",protocol=\"%s\"} %d\n",
                        sniffer.getId(), entry.getKey(), entry.getValue()));
            }
        }

        // Приложения
        if (metrics.getApplicationsMap() != null) {
            for (Map.Entry<String, Long> entry : metrics.getApplicationsMap().entrySet()) {
                sb.append(String.format("sniffer_app_packets{sniffer=\"%s\",app=\"%s\"} %d\n",
                        sniffer.getId(), entry.getKey(), entry.getValue()));
            }
        }

        // Health метрики
        sb.append("# HELP sniffer_cpu_usage CPU usage percentage\n");
        sb.append("# TYPE sniffer_cpu_usage gauge\n");
        sb.append(String.format("sniffer_cpu_usage{sniffer=\"%s\"} %f\n",
                sniffer.getId(), metrics.getCpuUsage()));

        sb.append("# HELP sniffer_memory_bytes Memory usage in bytes\n");
        sb.append("# TYPE sniffer_memory_bytes gauge\n");
        sb.append(String.format("sniffer_memory_bytes{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getMemoryBytes()));

        sb.append("# HELP sniffer_uptime_seconds Uptime in seconds\n");
        sb.append("# TYPE sniffer_uptime_seconds counter\n");
        sb.append(String.format("sniffer_uptime_seconds{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getUptimeSeconds()));

        sb.append("# HELP sniffer_goroutines Number of goroutines\n");
        sb.append("# TYPE sniffer_goroutines gauge\n");
        sb.append(String.format("sniffer_goroutines{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getNumGoroutines()));

        sb.append("# HELP sniffer_go_version Go version\n");
        sb.append("# TYPE sniffer_go_version gauge\n");
        sb.append(String.format("sniffer_go_version{sniffer=\"%s\"} 1\n",
                sniffer.getId()));
        sb.append(String.format("sniffer_go_version_info{sniffer=\"%s\",version=\"%s\"} 1\n",
                sniffer.getId(), metrics.getGoVersion()));

        // Скорости
        sb.append("# HELP sniffer_packets_per_second Current packets per second\n");
        sb.append("# TYPE sniffer_packets_per_second gauge\n");
        sb.append(String.format("sniffer_packets_per_second{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getPacketsPerSecond()));

        sb.append("# HELP sniffer_bytes_per_second Current bytes per second\n");
        sb.append("# TYPE sniffer_bytes_per_second gauge\n");
        sb.append(String.format("sniffer_bytes_per_second{sniffer=\"%s\"} %f\n",
                sniffer.getId(), metrics.getBytesPerSecond()));

        // TCP метрики
        sb.append("# HELP sniffer_tcp_connections Active TCP connections\n");
        sb.append("# TYPE sniffer_tcp_connections gauge\n");
        sb.append(String.format("sniffer_tcp_connections{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpConnections()));

        sb.append("# HELP sniffer_tcp_retransmissions TCP retransmissions\n");
        sb.append("# TYPE sniffer_tcp_retransmissions counter\n");
        sb.append(String.format("sniffer_tcp_retransmissions{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpRetransmissions()));

        return sb.toString();
    }
}
