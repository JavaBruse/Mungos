package capture

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func (s *Sniffer) BuildBPFFilter(filters []string) string {
	var parts []string
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		switch {
		case strings.Contains(f, ":"):
			ipPort := strings.SplitN(f, ":", 2)
			if net.ParseIP(ipPort[0]) != nil && isPort(ipPort[1]) {
				parts = append(parts, fmt.Sprintf("(host %s and port %s)", ipPort[0], ipPort[1]))
			}
		case net.ParseIP(f) != nil: // просто IP
			parts = append(parts, fmt.Sprintf("host %s", f))
		case isPort(f): // просто порт
			parts = append(parts, fmt.Sprintf("port %s", f))
		default:
			if strings.ContainsAny(f, "()andor") || !strings.ContainsAny(f, " ;&|") {
				parts = append(parts, f)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " or ")
}

func isPort(s string) bool {
	port, err := strconv.Atoi(s)
	return err == nil && port > 0 && port < 65536
}
