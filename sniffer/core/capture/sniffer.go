package capture

import (
	"sniffer/core/logger"
	"time"
)

type Sniffer struct {
	device    string
	snaplen   int
	promisc   bool
	timeout   time.Duration
	BPFFilter string
	packetCh  chan *Packet
	controlCh chan string
	stopCh    chan struct{}
	worker    *captureWorker
}

func NewSniffer(device string, snaplen int, promisc bool, timeout time.Duration, BPFFilter string, bufferSize int) *Sniffer {
	return &Sniffer{
		device:    device,
		snaplen:   snaplen,
		promisc:   promisc,
		timeout:   timeout,
		BPFFilter: BPFFilter,
		packetCh:  make(chan *Packet, bufferSize),
		controlCh: make(chan string, 10),
		stopCh:    make(chan struct{}),
	}
}

func (s *Sniffer) Start() error {
	s.worker = newCaptureWorker(s.device, s.snaplen, s.promisc, s.timeout, s.BPFFilter, s.packetCh, s.controlCh, s.stopCh)
	go s.worker.run()
	return nil
}

func (s *Sniffer) Stop() {
	close(s.stopCh)
}

func (s *Sniffer) Packets() <-chan *Packet {
	return s.packetCh
}

func (s *Sniffer) UpdateFilter(newFilter string) {
	logger.Info("Applying new filter: %s", newFilter)
	s.BPFFilter = newFilter
	select {
	case s.controlCh <- newFilter:
	default:
		logger.Warn("Control channel full, filter update dropped")
	}
}
