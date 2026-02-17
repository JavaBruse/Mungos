package capture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet — доменная модель пакета (чистая, без зависимостей)
type Packet struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Length    int
	TCPFlags  string
	TTL       uint8
	Payload   []byte
}

// NewPacketFromGopacket создаёт Packet из gopacket.Packet
func NewPacketFromGopacket(pkt gopacket.Packet) *Packet {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	p := &Packet{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		Protocol:  ip.Protocol.String(),
		Length:    pkt.Metadata().CaptureLength,
		TTL:       ip.TTL,
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

	return p
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
