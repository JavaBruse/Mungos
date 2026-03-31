package com.JavaBruse.core.config;

import com.JavaBruse.core.security.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mitre.dsmiley.httpproxy.ProxyServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.http.HttpRequest;
import org.springframework.core.Ordered;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class GrafanaProxyConfig {
    private final JwtService jwtService;
    private final String GRAFANA_URL = "http://mungos-grafana:3000";

    @Bean
    public ServletRegistrationBean<ProxyServlet> grafanaServlet() {
        ProxyServlet proxyServlet = new ProxyServlet() {

            @Override
            protected void service(HttpServletRequest servletRequest, jakarta.servlet.http.HttpServletResponse servletResponse)
                    throws jakarta.servlet.ServletException, java.io.IOException {
                String jwt = resolveJwt(servletRequest);

                if (jwt == null) {
                    log.warn("Access denied for Grafana proxy: No valid token found");
                    servletResponse.sendError(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN, "Access Denied: Invalid Token");
                    return;
                }

                super.service(servletRequest, servletResponse);
            }

            private String resolveJwt(HttpServletRequest request) {
                String jwt = null;
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    jwt = authHeader.substring(7);
                }
                if (jwt == null) {
                    jwt = request.getParameter("auth_token");
                    if (jwt != null && jwt.startsWith("Bearer ")) jwt = jwt.substring(7);
                }
                if (jwt == null && request.getCookies() != null) {
                    for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                        if ("grafana_auth".equals(cookie.getName())) {
                            String value = java.net.URLDecoder.decode(cookie.getValue(), java.nio.charset.StandardCharsets.UTF_8);
                            jwt = value.startsWith("Bearer ") ? value.substring(7) : value;
                            break;
                        }
                    }
                }
                return jwt;
            }

            @Override
            protected void copyRequestHeaders(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
                super.copyRequestHeaders(servletRequest, proxyRequest);
                String jwt = resolveJwt(servletRequest); // Используем наш метод

                if (jwt != null) {
                    try {
                        boolean isAdmin = jwtService.extractRole(jwt).contains("ROLE_ADMIN");
                        proxyRequest.addHeader("X-WEBAUTH-USER", isAdmin ? "admin" : "user");
                        proxyRequest.addHeader("X-WEBAUTH-ROLE", isAdmin ? "Admin" : "Viewer");
                    } catch (Exception e) {
                        log.error("JWT Parse error in proxy", e);
                    }
                }

                proxyRequest.removeHeaders("Cookie");
                proxyRequest.removeHeaders("Authorization");
                proxyRequest.removeHeaders("Host");
            }


            @Override
            protected String rewriteUrlFromRequest(HttpServletRequest servletRequest) {
                String path = servletRequest.getRequestURI();
                String newPath = path.replaceFirst("^/grafana/view", "")
                        .replaceFirst("^/grafana/edit", "")
                        .replaceFirst("^/grafana", "");

                if (!newPath.startsWith("/")) {
                    newPath = "/" + newPath;
                }

                String query = servletRequest.getQueryString();
                return GRAFANA_URL + newPath + (query != null ? "?" + query : "");
            }
        };

        ServletRegistrationBean<ProxyServlet> bean = new ServletRegistrationBean<>(proxyServlet, "/grafana/*");
        bean.addInitParameter("targetUri", GRAFANA_URL);
        bean.addInitParameter("log", "true");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}