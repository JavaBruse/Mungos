package capture

import (
	"fmt"
	"net"
	"sniffer/core/models"
	"sniffer/core/storage/memory"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewPacketFromGopacket(pkt gopacket.Packet) *models.Packet {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	p := &models.Packet{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		Protocol:  extractProtocolStack(pkt),
		Length:    pkt.Metadata().CaptureLength,
		TTL:       ip.TTL,
		SrcIPType: getIPType(ip.SrcIP.String()),
		DstIPType: getIPType(ip.DstIP.String()),
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.SrcPort = uint16(tcp.SrcPort)
		p.DstPort = uint16(tcp.DstPort)
		p.TCPFlags = formatTCPFlags(tcp)
		p.Payload = tcp.Payload
	}

	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		p.SrcPort = uint16(udp.SrcPort)
		p.DstPort = uint16(udp.DstPort)
		p.Payload = udp.Payload
	}

	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		p.SrcMAC = eth.SrcMAC.String()
		p.DstMAC = eth.DstMAC.String()

		if p.SrcMAC != "" {
			p.SrcVendor = memory.GetVendor(p.SrcMAC, p.SrcIP, p.SrcPort)
		}
		if p.DstMAC != "" {
			p.DstVendor = memory.GetVendor(p.DstMAC, p.DstIP, p.DstPort)
		}
	}

	return p
}

func getIPType(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "unknown"
	}

	// Loopback (127.0.0.0/8, ::1)
	if parsedIP.IsLoopback() {
		return "private"
	}

	// Multicast (224.0.0.0/4, ff00::/8)
	if parsedIP.IsMulticast() {
		return "private"
	}

	// Link-local (169.254.0.0/16, fe80::/10)
	if parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
		return "private"
	}

	// Broadcast - явная проверка
	if isBroadcast(parsedIP) {
		return "private"
	}

	// Приватные диапазоны (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	// и IPv6 unique local (fc00::/7) - Go 1.17+ покрывает оба
	if parsedIP.IsPrivate() {
		return "private"
	}

	return "public"
}

func isBroadcast(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// 255.255.255.255
	if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
		return true
	}

	// Broadcast в сети (последний октет 255)
	if ip4[3] == 255 {
		return true
	}

	// Широковещательные адреса /16 и /8
	if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 0 && ip4[3] == 0 {
		return true
	}
	if ip4[0] == 255 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0 {
		return true
	}

	return false
}

func formatTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "S"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.FIN {
		flags += "F"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.URG {
		flags += "U"
	}
	return flags
}

func extractProtocolStack(pkt gopacket.Packet) []string {
	var stack []string

	for _, layer := range pkt.Layers() {
		stack = append(stack, layer.LayerType().String())
		switch l := layer.(type) {
		case *layers.TCP:
			portHints := getPortHint(uint16(l.SrcPort), uint16(l.DstPort))
			stack = append(stack, portHints...)

			if len(l.Payload) > 0 {
				if isHTTP(l.Payload) {
					stack = append(stack, "HTTP")
				} else if version := getTLSVersion(l.Payload); version != "" {
					stack = append(stack, version)
				}
			}
		case *layers.UDP:
			portHints := getPortHint(uint16(l.SrcPort), uint16(l.DstPort))
			stack = append(stack, portHints...)
		}
	}

	appLayer := pkt.ApplicationLayer()
	if appLayer != nil && len(appLayer.Payload()) > 0 {
		hasPayload := false
		for _, s := range stack {
			if s == "Payload" {
				hasPayload = true
				break
			}
		}
		if !hasPayload {
			stack = append(stack, "Payload")
		}
	}

	return stack
}

func isHTTP(payload []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/"}
	for _, method := range methods {
		if len(payload) >= len(method) && string(payload[:len(method)]) == method {
			return true
		}
	}
	return false
}

func getTLSVersion(payload []byte) string {
	if len(payload) < 3 {
		return ""
	}
	if payload[0] != 0x16 {
		return ""
	}

	if len(payload) < 5 {
		return ""
	}
	version := uint16(payload[1])<<8 | uint16(payload[2])
	switch version {
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	default:
		return "TLS"
	}
}

func getPortHint(portS uint16, portD uint16) []string {
	hints := map[uint16]string{
		20:    "FTP-data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		143:   "IMAP",
		161:   "SNMP",
		194:   "IRC",
		443:   "HTTPS",
		465:   "SMTPS",
		514:   "Syslog",
		587:   "SMTP-submit",
		631:   "IPP",
		993:   "IMAPS",
		995:   "POPS",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP-alt",
		8443:  "HTTPS-alt",
		9090:  "Prometheus",
		27017: "MongoDB",
	}

	var result []string

	if hint, ok := hints[portS]; ok {
		result = append(result, fmt.Sprintf("%d(<-%s)", portS, hint))
	}

	if hint, ok := hints[portD]; ok {
		result = append(result, fmt.Sprintf("%d(->%s)", portD, hint))
	}

	return result
}
