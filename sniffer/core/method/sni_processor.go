package method

import (
	"context"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"strings"
	"time"
)

type SNIProcessor struct {
	db *clickhouse.ClickHouseStorage
}

func NewSNIProcessor(db *clickhouse.ClickHouseStorage) *SNIProcessor {
	return &SNIProcessor{db: db}
}

// ProcessSNI - единая точка входа для обработки SNI
func (p *SNIProcessor) ProcessSNI(packet *models.Packet, sessionPackets []*models.Packet) *models.Packet {
	if packet == nil {
		return packet
	}

	packet.SNI = ExtractSNI(packet)

	if p.isSessionEnd(packet) {
		go p.classifySessionAsync(sessionPackets)
	}

	return packet
}

// достает домен из пакета
func ExtractSNI(packet *models.Packet) string {
	if packet == nil || len(packet.Payload) < 5 || packet.Payload[0] != 0x16 {
		return ""
	}

	payload := packet.Payload
	pos := 5

	if len(payload) < pos+1 || payload[pos] != 0x01 {
		return ""
	}
	pos++

	if len(payload) < pos+3 {
		return ""
	}
	pos += 3

	if len(payload) < pos+34 {
		return ""
	}
	pos += 34

	if len(payload) < pos+1 {
		return ""
	}
	sessionIDLen := int(payload[pos])
	pos++
	if len(payload) < pos+sessionIDLen {
		return ""
	}
	pos += sessionIDLen

	if len(payload) < pos+2 {
		return ""
	}
	cipherSuitesLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	if len(payload) < pos+cipherSuitesLen {
		return ""
	}
	pos += cipherSuitesLen

	if len(payload) < pos+1 {
		return ""
	}
	compMethodsLen := int(payload[pos])
	pos++
	if len(payload) < pos+compMethodsLen {
		return ""
	}
	pos += compMethodsLen

	if len(payload) < pos+2 {
		return ""
	}
	extensionsLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	end := pos + extensionsLen

	for pos+4 <= end && pos < len(payload) {
		extType := int(payload[pos])<<8 | int(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4

		if extType == 0x00 {
			if len(payload) < pos+2 {
				return ""
			}
			pos += 2
			if len(payload) < pos+1 || payload[pos] != 0x00 {
				return ""
			}
			pos++
			if len(payload) < pos+2 {
				return ""
			}
			nameLen := int(payload[pos])<<8 | int(payload[pos+1])
			pos += 2
			if len(payload) >= pos+nameLen {
				return string(payload[pos : pos+nameLen])
			}
			return ""
		}
		pos += extLen
	}
	return ""
}

func (p *SNIProcessor) isSessionEnd(packet *models.Packet) bool {
	return strings.Contains(packet.TCPFlags, "F") || strings.Contains(packet.TCPFlags, "R")
}

func (p *SNIProcessor) classifySessionAsync(packets []*models.Packet) {
	time.Sleep(1 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	service, _, _ := p.classifySession(ctx, packets)

	snis := make([]string, 0)
	for _, pkt := range packets {
		pkt.SNIService = service
		if pkt.SNI != "" {
			snis = append(snis, pkt.SNI)
		}
	}

	p.updateStats(ctx, service, snis)
}

func (p *SNIProcessor) classifySession(ctx context.Context, packets []*models.Packet) (string, float64, error) {
	sniSet := make(map[string]bool)
	for _, pkt := range packets {
		if pkt.SNI != "" {
			sniSet[pkt.SNI] = true
		}
	}

	services, err := p.db.GetAllServices(ctx)
	if err != nil {
		return "unknown", 0, err
	}

	bestService := "unknown"
	bestProb := 0.0

	for _, service := range services {
		prob := 1.0
		for sni := range sniSet {
			pProb, err := p.db.GetSNIProbability(ctx, service, sni)
			if err != nil {
				pProb = 0.01
			}
			prob *= pProb
		}
		prob *= 1.0 / float64(len(services))

		if prob > bestProb {
			bestProb = prob
			bestService = service
		}
	}

	return bestService, bestProb, nil
}

func (p *SNIProcessor) updateStats(ctx context.Context, service string, snis []string) error {
	for _, sni := range snis {
		if sni != "" {
			if err := p.db.UpdateSNIStat(ctx, service, sni); err != nil {
				return err
			}
		}
	}
	return nil
}
