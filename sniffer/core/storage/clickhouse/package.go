package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/models"
	"strings"
	"time"

	"github.com/google/uuid"
)

func createPacketsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS packets (
			packet_id String,
			timestamp DateTime64(9) CODEC(Delta, ZSTD),
			src_ip String,
			dst_ip String,
			src_port UInt16,
			dst_port UInt16,
			protocol_stack String,
			length UInt32,
			ttl UInt8,
			tcp_flags String,
			payload String,
			src_mac String,
			dst_mac String,
			src_vendor String,
			dst_vendor String,
			ja4_raw String,
			ja4_type String,
			ja4_application String,
			ja4_device String,
			ja4_os String,
			ja4_verified Bool,
			ja4_confidence UInt32,
			sni String,
			sni_service String,
			src_ip_type String,
			dst_ip_type String
		) ENGINE = MergeTree()
		ORDER BY (timestamp, src_ip, dst_ip)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) GetPackets(ctx context.Context, filter *pb.FilterExpression,
	limit, offset int32, snifferID string) ([]*pb.TrafficPacket, error) {

	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query, args := buildFilterQuery(filter, limit, offset)

	rows, err := c.conn.QueryContext(ctx, query, args...)
	if err != nil {
		c.reconnect()
		return nil, err
	}
	defer rows.Close()

	var packets []*pb.TrafficPacket
	for rows.Next() {
		var pkt pb.TrafficPacket
		var timestamp time.Time
		var ttl uint8
		var packetID string
		var ja4Verified bool
		var ja4Confidence uint32
		var protocolStackStr string

		err := rows.Scan(
			&packetID,
			&timestamp,
			&pkt.SrcIp,
			&pkt.DstIp,
			&pkt.SrcPort,
			&pkt.DstPort,
			&protocolStackStr,
			&pkt.Length,
			&ttl,
			&pkt.TcpFlags,
			&pkt.Payload,
			&pkt.SrcMac,
			&pkt.DstMac,
			&pkt.SrcVendor,
			&pkt.DstVendor,
			&pkt.Ja4Raw,
			&pkt.Ja4Type,
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
			&pkt.SrcIpType,
			&pkt.DstIpType,
		)
		if err != nil {
			continue
		}

		if protocolStackStr != "" {
			pkt.ProtocolStack = strings.Split(protocolStackStr, ",")
		}

		pkt.Timestamp = timestamp.UnixNano()
		pkt.PacketId = packetID
		pkt.Ttl = int32(ttl)
		pkt.Ja4Verified = ja4Verified
		pkt.Ja4Confidence = int32(ja4Confidence)

		packets = append(packets, &pkt)
	}

	return packets, nil
}

func (c *ClickHouseStorage) StreamPackets(ctx context.Context, filter *pb.FilterExpression,
	snifferID string, sendFunc func(*pb.TrafficPacket) error) error {

	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query, args := buildFilterQuery(filter, 10000, 0)

	rows, err := c.conn.QueryContext(ctx, query, args...)
	if err != nil {
		c.reconnect()
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var pkt pb.TrafficPacket
		var timestamp time.Time
		var ttl uint8
		var packetID string
		var ja4Verified bool
		var ja4Confidence uint32
		var protocolStackStr string

		err := rows.Scan(
			&packetID,
			&timestamp,
			&pkt.SrcIp,
			&pkt.DstIp,
			&pkt.SrcPort,
			&pkt.DstPort,
			&protocolStackStr,
			&pkt.Length,
			&ttl,
			&pkt.TcpFlags,
			&pkt.Payload,
			&pkt.SrcMac,
			&pkt.DstMac,
			&pkt.SrcVendor,
			&pkt.DstVendor,
			&pkt.Ja4Raw,
			&pkt.Ja4Type,
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
			&pkt.SrcIpType,
			&pkt.DstIpType,
		)
		if err != nil {
			continue
		}

		if protocolStackStr != "" {
			pkt.ProtocolStack = strings.Split(protocolStackStr, ",")
		}

		pkt.Timestamp = timestamp.UnixNano()
		pkt.PacketId = packetID
		pkt.Ttl = int32(ttl)
		pkt.Ja4Verified = ja4Verified
		pkt.Ja4Confidence = int32(ja4Confidence)

		if err := sendFunc(&pkt); err != nil {
			return err
		}
	}

	return nil
}

func (c *ClickHouseStorage) GetPacketPayload(ctx context.Context, packetID string) ([]byte, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `SELECT payload FROM packets WHERE packet_id = ? LIMIT 1`

	var payload string
	err := c.conn.QueryRowContext(ctx, query, packetID).Scan(&payload)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("packet not found")
	}
	if err != nil {
		c.reconnect()
		return nil, err
	}

	return []byte(payload), nil
}

func buildFilterQuery(filter *pb.FilterExpression, limit, offset int32) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if filter != nil {
		if len(filter.Protocols) > 0 {
			var protocolConditions []string
			for _, p := range filter.Protocols {
				protocolConditions = append(protocolConditions, "protocol_stack LIKE ?")
				args = append(args, "%"+p+"%")
			}
			conditions = append(conditions, "("+strings.Join(protocolConditions, " OR ")+")")
		}

		if len(filter.Ports) > 0 {
			placeholders := strings.Repeat("?,", len(filter.Ports))
			placeholders = placeholders[:len(placeholders)-1]
			conditions = append(conditions, fmt.Sprintf("(src_port IN (%s) OR dst_port IN (%s))", placeholders, placeholders))
			for _, p := range filter.Ports {
				args = append(args, p, p)
			}
		}

		if len(filter.Ips) > 0 {
			placeholders := strings.Repeat("?,", len(filter.Ips))
			placeholders = placeholders[:len(placeholders)-1]
			conditions = append(conditions, fmt.Sprintf("(src_ip IN (%s) OR dst_ip IN (%s))", placeholders, placeholders))
			for _, ip := range filter.Ips {
				args = append(args, ip, ip)
			}
		}

		if filter.StartTime > 0 {
			conditions = append(conditions, "timestamp >= ?")
			args = append(args, time.Unix(0, filter.StartTime))
		}

		if filter.EndTime > 0 {
			conditions = append(conditions, "timestamp <= ?")
			args = append(args, time.Unix(0, filter.EndTime))
		}

		if filter.TextSearch != "" {
			searchTerm := "%" + filter.TextSearch + "%"
			textConditions := []string{
				"payload LIKE ?",
				"src_mac LIKE ?", "dst_mac LIKE ?",
				"src_vendor LIKE ?", "dst_vendor LIKE ?",
				"ja4_raw LIKE ?", "ja4_application LIKE ?", "ja4_device LIKE ?", "ja4_os LIKE ?",
				"sni LIKE ?", "sni_service LIKE ?",
			}

			placeholders := strings.Repeat("?,", len(textConditions))
			placeholders = placeholders[:len(placeholders)-1]

			conditions = append(conditions, "("+strings.Join(textConditions, " OR ")+")")

			for i := 0; i < len(textConditions); i++ {
				args = append(args, searchTerm)
			}
		}

		if filter.KnownOnly {
			conditions = append(conditions, "(ja4_raw != '' OR sni != '')")
		}
		if filter.UnknownOnly {
			conditions = append(conditions, "(ja4_raw = '' AND sni = '')")
		}
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
        SELECT packet_id, timestamp, src_ip, dst_ip, src_port, dst_port, 
               protocol_stack, length, ttl, tcp_flags, payload,
               src_mac, dst_mac, src_vendor, dst_vendor,
               ja4_raw, ja4_type, ja4_application, ja4_device, ja4_os, 
               ja4_verified, ja4_confidence, sni, sni_service,
			   src_ip_type, dst_ip_type
        FROM packets
        WHERE %s
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    `, whereClause)

	args = append(args, limit, offset)

	return query, args
}

func (c *ClickHouseStorage) SavePackets(packets []*models.Packet) error {
	if !c.ensureConnection() || len(packets) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		c.reconnect()
		return err
	}
	defer tx.Rollback()

	query := `
		INSERT INTO packets (
			packet_id, timestamp, src_ip, dst_ip, src_port, dst_port,
			protocol_stack, length, ttl, tcp_flags, payload,
			src_mac, dst_mac, src_vendor, dst_vendor,
			ja4_raw, ja4_type, ja4_application, ja4_device, 
			ja4_os, ja4_verified, ja4_confidence, sni, 
			sni_service, src_ip_type, dst_ip_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, pkt := range packets {
		packetID := uuid.New().String()
		payload := string(pkt.Payload)
		if len(payload) > 10000 {
			payload = payload[:10000]
		}

		protocolStack := strings.Join(pkt.Protocol, ",")

		_, err = stmt.ExecContext(ctx,
			packetID,
			pkt.Timestamp,
			pkt.SrcIP,
			pkt.DstIP,
			pkt.SrcPort,
			pkt.DstPort,
			protocolStack,
			pkt.Length,
			pkt.TTL,
			pkt.TCPFlags,
			payload,
			pkt.SrcMAC,
			pkt.DstMAC,
			pkt.SrcVendor,
			pkt.DstVendor,
			pkt.JA4Raw,
			pkt.JA4Type,
			pkt.JA4Application,
			pkt.JA4Device,
			pkt.JA4OS,
			pkt.JA4Verified,
			pkt.JA4Confidence,
			pkt.SNI,
			pkt.SNIService,
			pkt.SrcIPType,
			pkt.DstIPType,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetConnectionInsightByPacket - аналитика по соединению на основе packet_id
func (c *ClickHouseStorage) GetConnectionInsightByPacket(ctx context.Context, packetID string) (*models.ConnectionInsight, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	// 1. Получаем пакет по ID
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var srcIPType, dstIPType string

	err := c.conn.QueryRowContext(ctx, `
		SELECT src_ip, dst_ip, src_port, dst_port, src_ip_type, dst_ip_type
		FROM packets
		WHERE packet_id = ?
		LIMIT 1
	`, packetID).Scan(&srcIP, &dstIP, &srcPort, &dstPort, &srcIPType, &dstIPType)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("packet not found")
	}
	if err != nil {
		return nil, err
	}

	// 2. Определяем localIP, remoteIP, remotePort
	var localIP, remoteIP string
	var remotePort uint16

	if srcIPType == "private" || srcIPType == "local" {
		localIP = srcIP
		remoteIP = dstIP
		remotePort = dstPort
	} else {
		localIP = dstIP
		remoteIP = srcIP
		remotePort = srcPort
	}

	// 3. Получаем аналитику
	query := `
		SELECT
			groupUniqArray(src_port) as local_ports,
			COUNT() as total_packets,
			SUM(length) as total_bytes,
			MIN(timestamp) as first_time,
			MAX(timestamp) as last_time,
			COUNT(CASE WHEN tcp_flags LIKE '%S%' AND tcp_flags NOT LIKE '%A%' THEN 1 END) as syn_count,
			COUNT(CASE WHEN tcp_flags LIKE '%F%' THEN 1 END) as fin_count,
			COUNT(CASE WHEN tcp_flags LIKE '%R%' THEN 1 END) as rst_count,
			COUNT(CASE WHEN ja4_raw != '' OR sni != '' THEN 1 END) as identified_packets,
			groupUniqArray((
				ja4_raw, ja4_application, ja4_device, ja4_os,
				sni, sni_service
			)) as identification_groups
		FROM packets
		WHERE (dst_ip = ? AND dst_port = ?) 
		OR (src_ip = ? AND src_port = ?)
	`

	var insight models.ConnectionInsight
	var localPorts []uint16
	var firstTime, lastTime time.Time
	var identificationGroups [][]interface{}

	err = c.conn.QueryRowContext(ctx, query,
		remoteIP, remotePort,
		remoteIP, remotePort,
	).Scan(
		&localPorts,
		&insight.TotalPackets,
		&insight.TotalBytes,
		&firstTime,
		&lastTime,
		&insight.SynCount,
		&insight.FinCount,
		&insight.RstCount,
		&insight.IdentifiedPackets,
		&identificationGroups,
	)

	if err != nil {
		return nil, err
	}

	insight.LocalIP = localIP
	insight.LocalPorts = localPorts
	insight.RemoteIP = remoteIP
	insight.RemotePort = remotePort
	insight.FirstPacketTime = firstTime.UnixNano()
	insight.LastPacketTime = lastTime.UnixNano()

	// 4. Собираем кандидатов по hop-ам
	ja4Map := make(map[string]*models.JA4Candidate)
	sniMap := make(map[string]*models.SNICandidate)

	// Hop 1: точное совпадение (remoteIP, remotePort) из текущего соединения
	c.collectHop1Candidates(identificationGroups, ja4Map, sniMap, ctx)

	// Если не набрали 5, идём на Hop 2
	if len(ja4Map)+len(sniMap) < 5 {
		c.collectHopCandidates(ctx, remoteIP, remotePort, 2, ja4Map, sniMap, 5)
	}

	// Если не набрали 5, идём на Hop 3 (/24)
	if len(ja4Map)+len(sniMap) < 5 {
		subnet24 := getSubnet24(remoteIP)
		if subnet24 != "" {
			c.collectHopCandidatesBySubnet(ctx, subnet24, 3, ja4Map, sniMap, 5)
		}
	}

	// Если не набрали 5, идём на Hop 4 (/16)
	if len(ja4Map)+len(sniMap) < 5 {
		subnet16 := getSubnet16(remoteIP)
		if subnet16 != "" {
			c.collectHopCandidatesBySubnet(ctx, subnet16, 4, ja4Map, sniMap, 5)
		}
	}

	// Конвертируем мапы в слайсы
	for _, cand := range ja4Map {
		insight.JA4Candidates = append(insight.JA4Candidates, *cand)
	}
	for _, cand := range sniMap {
		insight.SNICandidates = append(insight.SNICandidates, *cand)
	}

	return &insight, nil
}

// collectHop1Candidates - собирает кандидатов из текущего соединения
func (c *ClickHouseStorage) collectHop1Candidates(
	identificationGroups [][]interface{},
	ja4Map map[string]*models.JA4Candidate,
	sniMap map[string]*models.SNICandidate,
	ctx context.Context,
) {
	for _, group := range identificationGroups {
		ja4Raw := toString(group[0])
		ja4App := toString(group[1])
		ja4Device := toString(group[2])
		ja4OS := toString(group[3])
		sni := toString(group[4])
		sniService := toString(group[5])

		if ja4Raw != "" {
			if _, exists := ja4Map[ja4Raw]; !exists {
				entry, _ := c.LookupJA4(ctx, ja4Raw)
				id := ""
				confidence := 0
				if entry != nil {
					id = entry.ID
					confidence = int(entry.ObservationCount)
				}
				ja4Map[ja4Raw] = &models.JA4Candidate{
					ID:          id,
					Fingerprint: ja4Raw,
					Application: ja4App,
					Device:      ja4Device,
					OS:          ja4OS,
					Count:       1,
					Confidence:  confidence,
					Hop:         1,
				}
			} else {
				ja4Map[ja4Raw].Count++
			}
		}

		if sni != "" {
			if _, exists := sniMap[sni]; !exists {
				entry, _ := c.GetSNIEntry(ctx, sni)
				id := ""
				confidence := 0
				if entry != nil {
					id = entry.ID
					confidence = int(entry.OccurrenceCount)
				}
				sniMap[sni] = &models.SNICandidate{
					ID:         id,
					SNI:        sni,
					Service:    sniService,
					Count:      1,
					Confidence: confidence,
					Hop:        1,
				}
			} else {
				sniMap[sni].Count++
			}
		}
	}
}

// collectHopCandidates - собирает кандидатов по IP и порту (Hop 2)
func (c *ClickHouseStorage) collectHopCandidates(
	ctx context.Context,
	remoteIP string,
	remotePort uint16,
	hop int,
	ja4Map map[string]*models.JA4Candidate,
	sniMap map[string]*models.SNICandidate,
	maxTotal int,
) {
	needed := maxTotal - (len(ja4Map) + len(sniMap))
	if needed <= 0 {
		return
	}

	// JA4 кандидаты
	ja4Query := `
		SELECT 
			ja4_raw,
			any(ja4_application) as ja4_app,
			any(ja4_device) as ja4_device,
			any(ja4_os) as ja4_os,
			COUNT() as count
		FROM packets
		WHERE dst_ip = ? AND ja4_raw != ''
		GROUP BY ja4_raw
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := c.conn.QueryContext(ctx, ja4Query, remoteIP, needed*2)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if len(ja4Map)+len(sniMap) >= maxTotal {
				break
			}
			var cand models.JA4Candidate
			var fingerprint string
			err := rows.Scan(&fingerprint, &cand.Application, &cand.Device, &cand.OS, &cand.Count)
			if err == nil {
				if _, exists := ja4Map[fingerprint]; exists {
					continue
				}
				cand.Fingerprint = fingerprint
				entry, _ := c.LookupJA4(ctx, fingerprint)
				if entry != nil {
					cand.ID = entry.ID
					cand.Confidence = int(entry.ObservationCount)
				}
				cand.Hop = hop
				ja4Map[fingerprint] = &cand
			}
		}
	}

	// SNI кандидаты
	needed = maxTotal - (len(ja4Map) + len(sniMap))
	if needed <= 0 {
		return
	}

	sniQuery := `
		SELECT 
			sni,
			any(sni_service) as sni_service,
			COUNT() as count
		FROM packets
		WHERE dst_ip = ? AND sni != ''
		GROUP BY sni
		ORDER BY count DESC
		LIMIT ?
	`

	rows2, err := c.conn.QueryContext(ctx, sniQuery, remoteIP, needed*2)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			if len(ja4Map)+len(sniMap) >= maxTotal {
				break
			}
			var cand models.SNICandidate
			err := rows2.Scan(&cand.SNI, &cand.Service, &cand.Count)
			if err == nil {
				if _, exists := sniMap[cand.SNI]; exists {
					continue
				}
				entry, _ := c.GetSNIEntry(ctx, cand.SNI)
				if entry != nil {
					cand.ID = entry.ID
					cand.Confidence = int(entry.OccurrenceCount)
				}
				cand.Hop = hop
				sniMap[cand.SNI] = &cand
			}
		}
	}
}

// collectHopCandidatesBySubnet - собирает кандидатов по подсети (Hop 3 и 4)
func (c *ClickHouseStorage) collectHopCandidatesBySubnet(
	ctx context.Context,
	subnet string,
	hop int,
	ja4Map map[string]*models.JA4Candidate,
	sniMap map[string]*models.SNICandidate,
	maxTotal int,
) {
	needed := maxTotal - (len(ja4Map) + len(sniMap))
	if needed <= 0 {
		return
	}

	// JA4 кандидаты по подсети
	ja4Query := `
		SELECT 
			ja4_raw,
			any(ja4_application) as ja4_app,
			any(ja4_device) as ja4_device,
			any(ja4_os) as ja4_os,
			COUNT() as count
		FROM packets
		WHERE dst_ip LIKE ? AND ja4_raw != ''
		GROUP BY ja4_raw
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := c.conn.QueryContext(ctx, ja4Query, subnet+"%", needed*2)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if len(ja4Map)+len(sniMap) >= maxTotal {
				break
			}
			var cand models.JA4Candidate
			var fingerprint string
			err := rows.Scan(&fingerprint, &cand.Application, &cand.Device, &cand.OS, &cand.Count)
			if err == nil {
				if _, exists := ja4Map[fingerprint]; exists {
					continue
				}
				cand.Fingerprint = fingerprint
				entry, _ := c.LookupJA4(ctx, fingerprint)
				if entry != nil {
					cand.ID = entry.ID
					cand.Confidence = int(entry.ObservationCount)
				}
				cand.Hop = hop
				ja4Map[fingerprint] = &cand
			}
		}
	}

	needed = maxTotal - (len(ja4Map) + len(sniMap))
	if needed <= 0 {
		return
	}

	// SNI кандидаты по подсети
	sniQuery := `
		SELECT 
			sni,
			any(sni_service) as sni_service,
			COUNT() as count
		FROM packets
		WHERE dst_ip LIKE ? AND sni != ''
		GROUP BY sni
		ORDER BY count DESC
		LIMIT ?
	`

	rows2, err := c.conn.QueryContext(ctx, sniQuery, subnet+"%", needed*2)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			if len(ja4Map)+len(sniMap) >= maxTotal {
				break
			}
			var cand models.SNICandidate
			err := rows2.Scan(&cand.SNI, &cand.Service, &cand.Count)
			if err == nil {
				if _, exists := sniMap[cand.SNI]; exists {
					continue
				}
				entry, _ := c.GetSNIEntry(ctx, cand.SNI)
				if entry != nil {
					cand.ID = entry.ID
					cand.Confidence = int(entry.OccurrenceCount)
				}
				cand.Hop = hop
				sniMap[cand.SNI] = &cand
			}
		}
	}
}

// getSubnet24 - возвращает первые 3 октета IP с точкой
func getSubnet24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2] + "."
	}
	return ""
}

// getSubnet16 - возвращает первые 2 октета IP с точкой
func getSubnet16(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1] + "."
	}
	return ""
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// UpdateConnectionInsight - обновляет JA4 и SNI для всех пакетов соединения
func (c *ClickHouseStorage) UpdateConnectionInsight(ctx context.Context, packetID, ja4EntryID, sniEntryID string) (string, uint16, *models.Ja4Entry, *models.SNIEntry, error) {
	if !c.ensureConnection() {
		return "", 0, nil, nil, fmt.Errorf("storage not available")
	}

	// 1. Получаем данные JA4 и SNI
	var ja4 *models.Ja4Entry
	var sni *models.SNIEntry
	var err error

	if ja4EntryID != "" {
		ja4, err = c.GetJA4ByID(ctx, ja4EntryID)
		if err != nil {
			return "", 0, nil, nil, fmt.Errorf("failed to get JA4 entry: %v", err)
		}
	}

	if sniEntryID != "" {
		sni, err = c.GetSNIByID(ctx, sniEntryID)
		if err != nil {
			return "", 0, nil, nil, fmt.Errorf("failed to get SNI entry: %v", err)
		}
	}

	// 2. Получаем параметры соединения по packet_id
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var srcIPType, dstIPType string

	err = c.conn.QueryRowContext(ctx, `
		SELECT src_ip, dst_ip, src_port, dst_port, src_ip_type, dst_ip_type
		FROM packets
		WHERE packet_id = ?
		LIMIT 1
	`, packetID).Scan(&srcIP, &dstIP, &srcPort, &dstPort, &srcIPType, &dstIPType)

	if err == sql.ErrNoRows {
		return "", 0, nil, nil, fmt.Errorf("packet not found")
	}
	if err != nil {
		return "", 0, nil, nil, err
	}

	// 3. Определяем remoteIP, remotePort
	var remoteIP string
	var remotePort uint16

	if srcIPType == "private" || srcIPType == "local" {
		remoteIP = dstIP
		remotePort = dstPort
	} else {
		remoteIP = srcIP
		remotePort = srcPort
	}

	// 4. Подготавливаем данные для обновления
	ja4Raw := ""
	ja4App := ""
	ja4Device := ""
	ja4OS := ""
	ja4Verified := false
	ja4Confidence := int32(0)

	if ja4 != nil {
		ja4Raw = ja4.Fingerprint
		ja4App = ja4.Application
		ja4Device = ja4.Device
		ja4OS = ja4.OS
		ja4Verified = ja4.Verified
		ja4Confidence = int32(ja4.ObservationCount)
	}

	sniValue := ""
	sniService := ""

	if sni != nil {
		sniValue = sni.SNI
		sniService = sni.Service
	}

	// 5. Обновляем только те пакеты, у которых ещё нет идентификации
	query := `
		ALTER TABLE packets UPDATE 
			ja4_raw = ?,
			ja4_type = ?,
			ja4_application = ?,
			ja4_device = ?,
			ja4_os = ?,
			ja4_verified = ?,
			ja4_confidence = ?,
			sni = ?,
			sni_service = ?
		WHERE (
			(dst_ip = ? AND dst_port = ?)
			OR 
			(src_ip = ? AND src_port = ?)
		)
		AND (ja4_raw = '' OR sni = '')
	`

	ja4Type := ""
	if ja4 != nil {
		ja4Type = ja4.FingerprintType
	}

	_, err = c.conn.ExecContext(ctx, query,
		ja4Raw, ja4Type, ja4App, ja4Device, ja4OS, ja4Verified, ja4Confidence,
		sniValue, sniService,
		remoteIP, remotePort,
		remoteIP, remotePort,
	)

	if err != nil {
		return "", 0, nil, nil, err
	}

	return remoteIP, remotePort, ja4, sni, nil
}

// GetServiceRules - получить все примененные правила
func (c *ClickHouseStorage) GetServiceRules(ctx context.Context) ([]ServiceRuleData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT DISTINCT dst_ip, dst_port, ja4_raw, sni
		FROM packets
		WHERE (ja4_raw != '' OR sni != '')
		  AND dst_ip_type = 'public'
	`

	rows, err := c.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ServiceRuleData
	for rows.Next() {
		var rule ServiceRuleData
		if err := rows.Scan(&rule.DstIP, &rule.DstPort, &rule.JA4Raw, &rule.SNIRaw); err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

type ServiceRuleData struct {
	DstIP   string
	DstPort uint16
	JA4Raw  string
	SNIRaw  string
}

// UpdatePacketsInsight - обновляет JA4 и SNI для всех пакетов соединения по IP:Port (только пустые поля)
func (c *ClickHouseStorage) UpdatePacketsInsight(ctx context.Context, targetIP string, targetPort uint16, ja4Entry *models.Ja4Entry, sniEntry *models.SNIEntry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("storage not available")
	}

	ja4Raw := ""
	ja4App := ""
	ja4Device := ""
	ja4OS := ""
	ja4Verified := false
	ja4Confidence := int32(0)
	ja4Type := ""

	sniValue := ""
	sniService := ""

	if ja4Entry != nil {
		ja4Raw = ja4Entry.Fingerprint
		ja4App = ja4Entry.Application
		ja4Device = ja4Entry.Device
		ja4OS = ja4Entry.OS
		ja4Verified = ja4Entry.Verified
		ja4Confidence = int32(ja4Entry.ObservationCount)
		ja4Type = ja4Entry.FingerprintType
	}

	if sniEntry != nil {
		sniValue = sniEntry.SNI
		sniService = sniEntry.Service
	}

	// Обновляем JA4, если он пустой
	if ja4Entry != nil {
		queryJA4 := `
			ALTER TABLE packets UPDATE 
				ja4_raw = ?,
				ja4_type = ?,
				ja4_application = ?,
				ja4_device = ?,
				ja4_os = ?,
				ja4_verified = ?,
				ja4_confidence = ?
			WHERE ((dst_ip = ? AND dst_port = ?) OR (src_ip = ? AND src_port = ?))
			AND ja4_raw = ''
		`
		if _, err := c.conn.ExecContext(ctx, queryJA4, ja4Raw, ja4Type, ja4App, ja4Device, ja4OS, ja4Verified, ja4Confidence, targetIP, targetPort, targetIP, targetPort); err != nil {
			return err
		}
	}

	// Обновляем SNI, если он пустой
	if sniEntry != nil {
		querySNI := `
			ALTER TABLE packets UPDATE 
				sni = ?,
				sni_service = ?
			WHERE ((dst_ip = ? AND dst_port = ?) OR (src_ip = ? AND src_port = ?))
			AND sni = ''
		`
		if _, err := c.conn.ExecContext(ctx, querySNI, sniValue, sniService, targetIP, targetPort, targetIP, targetPort); err != nil {
			return err
		}
	}

	return nil
}
