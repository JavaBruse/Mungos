package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffer отвечает за захват трафика
type Sniffer struct {
	device   string
	snaplen  int
	promisc  bool
	timeout  time.Duration
	filter   string
	packetCh chan *Packet
	stopCh   chan struct{}
}

// NewSniffer создаёт новый экземпляр Sniffer
func NewSniffer(device string, snaplen int, promisc bool, timeout time.Duration, filter string, bufferSize int) *Sniffer {
	return &Sniffer{
		device:   device,
		snaplen:  snaplen,
		promisc:  promisc,
		timeout:  timeout,
		filter:   filter,
		packetCh: make(chan *Packet, bufferSize),
		stopCh:   make(chan struct{}),
	}
}

// Start запускает захват трафика (блокирующий)
func (s *Sniffer) Start() error {
	handle, err := pcap.OpenLive(s.device, int32(s.snaplen), s.promisc, s.timeout)
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}
	defer handle.Close()

	if s.filter != "" {
		if err := handle.SetBPFFilter(s.filter); err != nil {
			return fmt.Errorf("set filter: %w", err)
		}
	}

	fmt.Printf("Sniffer started on %s\n", s.device)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-s.stopCh:
			fmt.Println("Sniffer stopped")
			return nil
		case pkt := <-packetSource.Packets():
			if packet := NewPacketFromGopacket(pkt); packet != nil {
				select {
				case s.packetCh <- packet:
				default:
					// Канал переполнен — пропускаем
				}
			}
		}
	}
}

// Stop останавливает захват
func (s *Sniffer) Stop() {
	close(s.stopCh)
}

// Packets возвращает канал с пакетами
func (s *Sniffer) Packets() <-chan *Packet {
	return s.packetCh
}
