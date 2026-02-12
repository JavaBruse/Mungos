package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device     = flag.String("i", "eth0", "Network interface to capture")
	snaplen    = flag.Int("s", 65535, "Snapshot length")
	promisc    = flag.Bool("p", true, "Promiscuous mode")
	timeout    = flag.Duration("t", 0, "Capture timeout (0 = forever)")
	outputFile = flag.String("o", "packets.log", "Output log file")
	bpfFilter  = flag.String("f", "", "BPF filter (e.g. 'tcp port 443')")
)

type PacketInfo struct {
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

func main() {
	flag.Parse()

	// Открываем файл для логов
	f, err := os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)

	// Открываем устройство для захвата
	handle, err := pcap.OpenLive(*device, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", *device, err)
	}
	defer handle.Close()

	// Применяем BPF фильтр если задан
	if *bpfFilter != "" {
		err = handle.SetBPFFilter(*bpfFilter)
		if err != nil {
			log.Fatalf("Error setting filter: %v", err)
		}
		fmt.Printf("BPF filter applied: %s\n", *bpfFilter)
	}

	fmt.Printf("Starting capture on interface: %s\n", *device)
	fmt.Printf("Output file: %s\n", *outputFile)
	fmt.Println("Press Ctrl+C to stop...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make(chan gopacket.Packet)

	// Обработка сигналов для graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Конкурентная обработка пакетов
	go func() {
		for packet := range packetSource.Packets() {
			packets <- packet
		}
		close(packets)
	}()

	// Worker pool для обработки пакетов
	for i := 0; i < 5; i++ {
		go packetWorker(packets, logger)
	}

	<-sigChan
	fmt.Println("\nStopping capture...")
}

func packetWorker(packets <-chan gopacket.Packet, logger *log.Logger) {
	for packet := range packets {
		info := parsePacket(packet)
		if info != nil {
			logPacket(info, logger)
			printPacket(info)
		}
	}
}

func parsePacket(packet gopacket.Packet) *PacketInfo {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)

	info := &PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		Protocol:  ip.Protocol.String(),
		Length:    packet.Metadata().CaptureLength,
		TTL:       ip.TTL,
	}

	// TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.TCPFlags = getTCPFlags(tcp)
		info.Payload = tcp.Payload
	}

	// UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Payload = udp.Payload
	}

	return info
}

func getTCPFlags(tcp *layers.TCP) string {
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

func logPacket(info *PacketInfo, logger *log.Logger) {
	logger.Printf("%s %s:%d -> %s:%d [%s] len=%d ttl=%d flags=%s",
		info.Timestamp.Format(time.RFC3339Nano),
		info.SrcIP, info.SrcPort,
		info.DstIP, info.DstPort,
		info.Protocol,
		info.Length,
		info.TTL,
		info.TCPFlags,
	)
}

func printPacket(info *PacketInfo) {
	fmt.Printf("%s %s:%d -> %s:%d [%s] len=%d flags=%s\n",
		info.Timestamp.Format("15:04:05.000000"),
		info.SrcIP, info.SrcPort,
		info.DstIP, info.DstPort,
		info.Protocol,
		info.Length,
		info.TCPFlags,
	)
}
