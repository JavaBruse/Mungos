package capture

import (
	"fmt"
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
	ruleCache *RuleCache
}

func newCaptureWorker(device string, snaplen int, promisc bool, timeout time.Duration, filter string,
	packetCh chan<- *models.Packet, controlCh <-chan string, stopCh <-chan struct{},
	db *clickhouse.ClickHouseStorage, ruleCache *RuleCache) *captureWorker {
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
		ruleCache: ruleCache,
	}
}

func fillPacketFromEntry(packet *models.Packet, entry *models.Ja4Entry) {
	if entry == nil {
		return
	}
	packet.JA4EntryID = entry.ID
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

	if w.ruleCache != nil && packet.DstIPType == "public" {
		key := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
		if rule := w.ruleCache.Get(key); rule != nil {
			if rule.JA4Entry != nil {
				fillPacketFromEntry(packet, rule.JA4Entry)
			}
			if rule.SNIEntry != nil {
				packet.SNIService = rule.SNIEntry.Service
				packet.SNIEntryID = rule.SNIEntry.ID
				if packet.SNI == "" {
					packet.SNI = rule.SNIEntry.SNI
				}
			}
			// Если уже есть идентификация, JA4/SNI анализ можно пропустить
			if packet.JA4EntryID != "" && packet.SNIEntryID != "" {
				return packet
			}
		}
	}

	// JA4 анализ
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		packet = method.ProcessJA4(packet, tcp, w.db)
		if packet.JA4Application != "" {
			logger.Info("ja4: %v", packet.JA4Application)
		}
	}

	// SNI извлечение
	processor := method.NewSNIProcessor(w.db)
	packet = processor.ProcessSNI(packet, nil)

	return packet
}

func (w *captureWorker) run() {
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
