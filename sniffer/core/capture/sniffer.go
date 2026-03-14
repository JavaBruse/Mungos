package capture

import (
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"time"
)

type Sniffer struct {
	device    string
	snaplen   int
	promisc   bool
	timeout   time.Duration
	BPFFilter string
	packetCh  chan *models.Packet
	controlCh chan string
	stopCh    chan struct{}
	worker    *captureWorker
	db        *clickhouse.ClickHouseStorage
}

func NewSniffer(device string, snaplen int, promisc bool, timeout time.Duration,
	BPFFilter string, bufferSize int, db *clickhouse.ClickHouseStorage) *Sniffer {
	return &Sniffer{
		device:    device,
		snaplen:   snaplen,
		promisc:   promisc,
		timeout:   timeout,
		BPFFilter: BPFFilter,
		packetCh:  make(chan *models.Packet, bufferSize),
		controlCh: make(chan string, 10),
		stopCh:    make(chan struct{}),
		db:        db,
	}
}

func (s *Sniffer) Start() error {
	s.worker = newCaptureWorker(
		s.device, s.snaplen, s.promisc, s.timeout, s.BPFFilter,
		s.packetCh, s.controlCh, s.stopCh, s.db,
	)
	go s.worker.run()
	return nil
}

func (s *Sniffer) Stop() {
	close(s.stopCh)
}

func (s *Sniffer) Packets() <-chan *models.Packet {
	return s.packetCh
}
