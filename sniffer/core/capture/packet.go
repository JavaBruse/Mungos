package capture

import (
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

	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		p.SrcMAC = eth.SrcMAC.String()
		p.DstMAC = eth.DstMAC.String()

		if p.SrcMAC != "" {
			p.SrcVendor = memory.GetVendor(p.SrcMAC)
		}
		if p.DstMAC != "" {
			p.DstVendor = memory.GetVendor(p.DstMAC)
		}
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
