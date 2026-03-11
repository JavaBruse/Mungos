package capture

import (
	"sniffer/core/logger"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type captureWorker struct {
	device    string
	snaplen   int
	promisc   bool
	timeout   time.Duration
	BPFFilter string
	packetCh  chan<- *Packet
	controlCh <-chan string
	stopCh    <-chan struct{}
}

func newCaptureWorker(device string, snaplen int, promisc bool, timeout time.Duration, filter string,
	packetCh chan<- *Packet, controlCh <-chan string, stopCh <-chan struct{}) *captureWorker {
	return &captureWorker{
		device:    device,
		snaplen:   snaplen,
		promisc:   promisc,
		timeout:   timeout,
		BPFFilter: filter,
		packetCh:  packetCh,
		controlCh: controlCh,
		stopCh:    stopCh,
	}
}

func (w *captureWorker) run() {
	for {
		w.runCapture()

		select {
		case <-w.stopCh:
			return
		case newFilter := <-w.controlCh:
			w.BPFFilter = newFilter
			logger.Info("Filter updated, restarting capture with: %s", newFilter)
		}
	}
}

func (w *captureWorker) runCapture() {
	handle, err := pcap.OpenLive(w.device, int32(w.snaplen), w.promisc, w.timeout)
	if err != nil {
		logger.Error("Failed to open device: %v", err)
		time.Sleep(5 * time.Second)
		return
	}
	defer handle.Close()

	if w.BPFFilter != "" {
		if err := handle.SetBPFFilter(w.BPFFilter); err != nil {
			logger.Error("Failed to set filter: %v", err)
			return
		}
	}

	logger.Info("Sniffer started on %s with filter: %s", w.device, w.BPFFilter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-w.stopCh:
			logger.Info("Sniffer stopped")
			return
		case <-w.controlCh:
			logger.Info("Filter update signal received, restarting capture...")
			return
		case pkt := <-packetSource.Packets():
			logger.Info("1. RAW PACKET RECEIVED!")

			if packet := NewPacketFromGopacket(pkt); packet != nil {
				logger.Info("PACKET PARSED: %s:%d -> %s:%d",
					packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort) // 2

				select {
				case w.packetCh <- packet:
					logger.Info("2. PACKET SENT TO CHANNEL")
				default:
					logger.Warn("3. Packet channel full, dropping packet")
				}
			} else {
				logger.Info("4. PACKET PARSE FAILED")
			}
		}
	}
}
