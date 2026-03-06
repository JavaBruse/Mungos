package com.JavaBruse.core.sniffer.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/proxy/prometheus")
public class PrometheusProxyController {

    @Value("${prometheus.url}")
    private String prometheusUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/**")
    public String proxyGet(HttpServletRequest request) {
        String path = request.getRequestURI().replace("/api/proxy/prometheus", "");
        String fullUrl = prometheusUrl + path;

        if (request.getQueryString() != null) {
            fullUrl += "?" + request.getQueryString();
        }

        return restTemplate.getForObject(fullUrl, String.class);
    }
}