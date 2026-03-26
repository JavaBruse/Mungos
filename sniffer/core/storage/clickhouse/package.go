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
			ja4_application String,
			ja4_device String,
			ja4_os String,
			ja4_verified Bool,
			ja4_confidence UInt32,
			sni String,
			sni_service String,
			ja4_entry_id String,
			sni_entry_id String,
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
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
			&pkt.Ja4Id,
			&pkt.SniId,
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
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
			&pkt.Ja4Id,
			&pkt.SniId,
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
			conditions = append(conditions, "ja4_entry_id != '' AND sni_entry_id != ''")
		}
		if filter.UnknownOnly {
			conditions = append(conditions, "ja4_entry_id = '' OR sni_entry_id = ''")
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
               ja4_raw, ja4_application, ja4_device, ja4_os, 
               ja4_verified, ja4_confidence, sni, sni_service,
			   ja4_entry_id, sni_entry_id, src_ip_type, dst_ip_type
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
			ja4_raw, ja4_application, ja4_device, ja4_os,
			ja4_verified, ja4_confidence, sni, sni_service,
			ja4_entry_id, sni_entry_id, src_ip_type, dst_ip_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			pkt.JA4Application,
			pkt.JA4Device,
			pkt.JA4OS,
			pkt.JA4Verified,
			pkt.JA4Confidence,
			pkt.SNI,
			pkt.SNIService,
			pkt.JA4EntryID,
			pkt.SNIEntryID,
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
			COUNT(CASE WHEN ja4_entry_id != '' OR sni_entry_id != '' THEN 1 END) as identified_packets,
			groupUniqArray((
				ja4_raw, ja4_application, ja4_device, ja4_os,
				sni, sni_service, ja4_entry_id, sni_entry_id
			)) as identification_groups
		FROM packets
		WHERE dst_ip = ? AND dst_port = ?
	`

	var insight models.ConnectionInsight
	var localPorts []uint16
	var firstTime, lastTime time.Time
	var identificationGroups [][]interface{}

	err = c.conn.QueryRowContext(ctx, query, remoteIP, remotePort).Scan(
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

	// Группируем идентификационные данные
	idMap := make(map[string]*models.IdentificData)
	for _, group := range identificationGroups {
		if len(group) < 8 {
			continue
		}

		ja4Raw := toString(group[0])
		ja4App := toString(group[1])
		ja4Device := toString(group[2])
		ja4OS := toString(group[3])
		sni := toString(group[4])
		sniService := toString(group[5])
		ja4EntryID := toString(group[6])
		sniEntryID := toString(group[7])

		key := ja4EntryID + "|" + sniEntryID

		if _, exists := idMap[key]; !exists {
			idMap[key] = &models.IdentificData{
				UniqueJA4Raw:         []string{},
				UniqueJA4Application: []string{},
				UniqueJA4Device:      []string{},
				UniqueJA4OS:          []string{},
				UniqueSNI:            []string{},
				UniqueSNIService:     []string{},
				UniqueJA4EntryID:     []string{},
				UniqueSNIEntryID:     []string{},
				RelatedAddressJa4:    []models.RelatedAddress{},
				RelatedAddressSNI:    []models.RelatedAddress{},
			}
		}

		idMap[key].UniqueJA4Raw = addUnique(idMap[key].UniqueJA4Raw, ja4Raw)
		idMap[key].UniqueJA4Application = addUnique(idMap[key].UniqueJA4Application, ja4App)
		idMap[key].UniqueJA4Device = addUnique(idMap[key].UniqueJA4Device, ja4Device)
		idMap[key].UniqueJA4OS = addUnique(idMap[key].UniqueJA4OS, ja4OS)
		idMap[key].UniqueSNI = addUnique(idMap[key].UniqueSNI, sni)
		idMap[key].UniqueSNIService = addUnique(idMap[key].UniqueSNIService, sniService)
		idMap[key].UniqueJA4EntryID = addUnique(idMap[key].UniqueJA4EntryID, ja4EntryID)
		idMap[key].UniqueSNIEntryID = addUnique(idMap[key].UniqueSNIEntryID, sniEntryID)
	}

	for _, data := range idMap {
		if len(data.UniqueJA4EntryID) > 0 {
			related, err := c.GetRelatedByJA4(ctx, data.UniqueJA4EntryID)
			if err == nil {
				data.RelatedAddressJa4 = related
			}
		}

		if len(data.UniqueSNIEntryID) > 0 {
			related, err := c.GetRelatedBySNI(ctx, data.UniqueSNIEntryID)
			if err == nil {
				data.RelatedAddressSNI = related
			}
		}
	}

	for _, data := range idMap {
		insight.IdentificData = append(insight.IdentificData, *data)
	}

	return &insight, nil
}

// toString - конвертирует interface{} в строку
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

// GetRelatedByJA4 - ищет все адреса, где встречаются указанные JA4EntryID (только публичные)
func (c *ClickHouseStorage) GetRelatedByJA4(ctx context.Context, ja4EntryIDs []string) ([]models.RelatedAddress, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			dst_ip,
			dst_port,
			COUNT() as count
		FROM packets
		WHERE ja4_entry_id IN (?)
			AND dst_ip_type = 'public'
		GROUP BY dst_ip, dst_port
		ORDER BY count DESC
		LIMIT 50
	`

	placeholders := strings.Repeat("?,", len(ja4EntryIDs))
	placeholders = placeholders[:len(placeholders)-1]
	query = strings.Replace(query, "(?)", "("+placeholders+")", 1)

	args := []interface{}{}
	for _, id := range ja4EntryIDs {
		args = append(args, id)
	}

	rows, err := c.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.RelatedAddress
	for rows.Next() {
		var addr models.RelatedAddress
		if err := rows.Scan(&addr.RemoteIP, &addr.RemotePort, &addr.Count); err != nil {
			continue
		}
		results = append(results, addr)
	}

	return results, nil
}

// GetRelatedBySNI - ищет все адреса, где встречаются указанные SNIEntryID (только публичные)
func (c *ClickHouseStorage) GetRelatedBySNI(ctx context.Context, sniEntryIDs []string) ([]models.RelatedAddress, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			dst_ip,
			dst_port,
			COUNT() as count
		FROM packets
		WHERE sni_entry_id IN (?)
			AND dst_ip_type = 'public'
		GROUP BY dst_ip, dst_port
		ORDER BY count DESC
		LIMIT 50
	`

	placeholders := strings.Repeat("?,", len(sniEntryIDs))
	placeholders = placeholders[:len(placeholders)-1]
	query = strings.Replace(query, "(?)", "("+placeholders+")", 1)

	args := []interface{}{}
	for _, id := range sniEntryIDs {
		args = append(args, id)
	}

	rows, err := c.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.RelatedAddress
	for rows.Next() {
		var addr models.RelatedAddress
		if err := rows.Scan(&addr.RemoteIP, &addr.RemotePort, &addr.Count); err != nil {
			continue
		}
		results = append(results, addr)
	}

	return results, nil
}

func addUnique(slice []string, value string) []string {
	if value == "" {
		return slice
	}
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
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

	// 4. Обновляем все поля в пакетах
	query := `
		ALTER TABLE packets UPDATE 
			ja4_entry_id = ?,
			ja4_raw = ?,
			ja4_application = ?,
			ja4_device = ?,
			ja4_os = ?,
			ja4_verified = ?,
			ja4_confidence = ?,
			sni_entry_id = ?,
			sni = ?,
			sni_service = ?
		WHERE (
			(dst_ip = ? AND dst_port = ?)
			OR 
			(src_ip = ? AND src_port = ?)
		)
		AND (ja4_entry_id = '' OR sni_entry_id = '')
	`

	ja4Raw := ""
	ja4App := ""
	ja4Device := ""
	ja4OS := ""
	ja4Verified := false
	ja4Confidence := int32(0)

	if ja4 != nil {
		ja4Raw = ja4.Fingerprint
		ja4App = ja4.Application
		if ja4.Device != "" {
			ja4Device = ja4.Device
		}
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

	_, err = c.conn.ExecContext(ctx, query,
		ja4EntryID, ja4Raw, ja4App, ja4Device, ja4OS, ja4Verified, ja4Confidence,
		sniEntryID, sniValue, sniService,
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
		SELECT DISTINCT dst_ip, dst_port, ja4_entry_id, sni_entry_id
		FROM packets
		WHERE (ja4_entry_id != '' OR sni_entry_id != '')
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
		if err := rows.Scan(&rule.DstIP, &rule.DstPort, &rule.JA4EntryID, &rule.SNIEntryID); err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

type ServiceRuleData struct {
	DstIP      string
	DstPort    uint16
	JA4EntryID string
	SNIEntryID string
}
