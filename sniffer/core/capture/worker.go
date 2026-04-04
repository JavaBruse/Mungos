package capture

import (
	"sniffer/core/logger"
	"sniffer/core/method"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type captureWorker struct {
	device    string
	snaplen   int
	promisc   bool
	timeout   time.Duration
	BPFFilter string
	packetCh  chan<- *models.Packet
	controlCh <-chan string
	stopCh    <-chan struct{}
	db        *clickhouse.ClickHouseStorage
}

func newCaptureWorker(device string, snaplen int, promisc bool, timeout time.Duration, filter string,
	packetCh chan<- *models.Packet, controlCh <-chan string, stopCh <-chan struct{},
	db *clickhouse.ClickHouseStorage) *captureWorker {
	return &captureWorker{
		device:    device,
		snaplen:   snaplen,
		promisc:   promisc,
		timeout:   timeout,
		BPFFilter: filter,
		packetCh:  packetCh,
		controlCh: controlCh,
		stopCh:    stopCh,
		db:        db,
	}
}

func fillPacketFromEntry(packet *models.Packet, entry *models.Ja4Entry) {
	if entry == nil {
		return
	}
	packet.JA4Type = entry.FingerprintType
	packet.JA4Raw = entry.Fingerprint
	packet.JA4Application = entry.Application
	packet.JA4Device = entry.Device
	packet.JA4OS = entry.OS
	packet.JA4Verified = entry.Verified
	packet.JA4Confidence = entry.ObservationCount
}

func (w *captureWorker) processPacket(pkt gopacket.Packet) *models.Packet {
	packet := NewPacketFromGopacket(pkt)
	if packet == nil {
		return nil
	}

	// Применяем правила из кэша (проверяем и dst, и src)
	ruleCache := GetRuleCache()
	if ruleCache != nil && ruleCache.ApplyRule(packet) {
		if packet.JA4Raw != "" && packet.SNI != "" {
			return packet
		}
	}

	// JA4 анализ
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		packet = method.ProcessJA4(packet, tcp, w.db)
	}

	// SNI обработка через процессор
	packet = method.GetSNIProcessor(w.db).ProcessSNI(packet, nil)
	if ruleCache := GetRuleCache(); ruleCache != nil {
		ruleCache.UpdateFromPacket(packet, w.db)
	}
	return packet
}

func (w *captureWorker) run() {
	device := w.device
	handle, err := pcap.OpenLive(w.device, int32(w.snaplen), w.promisc, w.timeout)
	if err != nil {
		logger.Warn("Failed to open device %s: %v, trying to find available interface", device, err)
		devices, err := pcap.FindAllDevs()
		if err != nil {
			logger.Error("Failed to find devices: %v", err)
			time.Sleep(5 * time.Second)
			return
		}
		if len(devices) == 0 {
			logger.Error("No network interfaces found")
			time.Sleep(5 * time.Second)
			return
		}
		device = devices[0].Name
		logger.Info("Using first available interface: %s", device)

		handle, err = pcap.OpenLive(device, int32(w.snaplen), w.promisc, w.timeout)
		if err != nil {
			logger.Error("Failed to open fallback device %s: %v", device, err)
			time.Sleep(5 * time.Second)
			return
		}
	}
	defer handle.Close()
	if w.BPFFilter != "" {
		if err := handle.SetBPFFilter(w.BPFFilter); err != nil {
			logger.Error("Failed to set filter: %v", err)
			return
		}
	}

	logger.Info("Sniffer started on %s with filter: %s", device, w.BPFFilter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-w.stopCh:
			logger.Info("Sniffer stopped")
			return
		case pkt := <-packetSource.Packets():
			if packet := w.processPacket(pkt); packet != nil {
				select {
				case w.packetCh <- packet:
				default:
					logger.Warn("Packet channel full, dropping packet")
				}
			}
		}
	}
}
