package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.DTO.SnifferResponseDTO;
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
    private final SnifferService snifferService;

    @Value("${server.port}")
    private String port;

    public List<Map<String, Object>> getClients() {
        List<SnifferResponseDTO> sniffers = snifferService.getAll();
        List<Map<String, Object>> result = new ArrayList<>();
        String baseTarget = "core-app:" + port;
        for (SnifferResponseDTO s : sniffers) {
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
        SnifferResponseDTO sniffer = snifferService.getAll().stream()
                .filter(x -> x.getId().equals(uuid.toString()))
                .findFirst()
                .orElseThrow(() -> new ConnectionException("Sniffer not found with id: " + uuid));

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

        // Известные порты (well known ports)
        if (metrics.getWellKnownPortsMap() != null) {
            for (Map.Entry<String, Long> entry : metrics.getWellKnownPortsMap().entrySet()) {
                sb.append(String.format("sniffer_well_known_ports{sniffer=\"%s\",port=\"%s\"} %d\n",
                        sniffer.getId(), entry.getKey(), entry.getValue()));
            }
        }

        // Топ сервисов по пакетам
        if (metrics.getTopServicesMap() != null) {
            for (Map.Entry<String, Long> entry : metrics.getTopServicesMap().entrySet()) {
                sb.append(String.format("sniffer_top_services{sniffer=\"%s\",service=\"%s\"} %d\n",
                        sniffer.getId(), entry.getKey(), entry.getValue()));
            }
        }

        // Топ сервисов по соединениям
        if (metrics.getTopServicesByConnectionsMap() != null) {
            for (Map.Entry<String, Long> entry : metrics.getTopServicesByConnectionsMap().entrySet()) {
                sb.append(String.format("sniffer_top_services_connections{sniffer=\"%s\",service=\"%s\"} %d\n",
                        sniffer.getId(), entry.getKey(), entry.getValue()));
            }
        }

        // Скорости
        sb.append("# HELP sniffer_packets_per_second Current packets per second (last 5 seconds)\n");
        sb.append("# TYPE sniffer_packets_per_second gauge\n");
        sb.append(String.format("sniffer_packets_per_second{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getPacketsPerSecond()));

        sb.append("# HELP sniffer_bytes_per_second Current bytes per second (last 5 seconds)\n");
        sb.append("# TYPE sniffer_bytes_per_second gauge\n");
        sb.append(String.format("sniffer_bytes_per_second{sniffer=\"%s\"} %f\n",
                sniffer.getId(), metrics.getBytesPerSecond()));

        // TCP метрики
        sb.append("# HELP sniffer_tcp_connections Active TCP connections\n");
        sb.append("# TYPE sniffer_tcp_connections gauge\n");
        sb.append(String.format("sniffer_tcp_connections{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpConnections()));

        sb.append("# HELP sniffer_tcp_syn_packets TCP SYN packets\n");
        sb.append("# TYPE sniffer_tcp_syn_packets counter\n");
        sb.append(String.format("sniffer_tcp_syn_packets{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpSynPackets()));

        sb.append("# HELP sniffer_tcp_fin_packets TCP FIN packets\n");
        sb.append("# TYPE sniffer_tcp_fin_packets counter\n");
        sb.append(String.format("sniffer_tcp_fin_packets{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpFinPackets()));

        sb.append("# HELP sniffer_tcp_rst_packets TCP RST packets\n");
        sb.append("# TYPE sniffer_tcp_rst_packets counter\n");
        sb.append(String.format("sniffer_tcp_rst_packets{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getTcpRstPackets()));

        // Known и Unknown пакеты (общие)
        sb.append("# HELP sniffer_known_packets_total Known packets count (with JA4 and SNI)\n");
        sb.append("# TYPE sniffer_known_packets_total counter\n");
        sb.append(String.format("sniffer_known_packets_total{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getAllKnow()));

        sb.append("# HELP sniffer_unknown_packets_total Unknown packets count (without JA4 or SNI)\n");
        sb.append("# TYPE sniffer_unknown_packets_total counter\n");
        sb.append(String.format("sniffer_unknown_packets_total{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getAllUnknow()));

        // Known и Unknown пакеты за последние 5 секунд
        sb.append("# HELP sniffer_known_packets_5sec Known packets in last 5 seconds\n");
        sb.append("# TYPE sniffer_known_packets_5sec gauge\n");
        sb.append(String.format("sniffer_known_packets_5sec{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getKnownPackets5Sec()));

        sb.append("# HELP sniffer_unknown_packets_5sec Unknown packets in last 5 seconds\n");
        sb.append("# TYPE sniffer_unknown_packets_5sec gauge\n");
        sb.append(String.format("sniffer_unknown_packets_5sec{sniffer=\"%s\"} %d\n",
                sniffer.getId(), metrics.getUnknownPackets5Sec()));

        return sb.toString();
    }
}
