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
			protocol String,
			length UInt32,
			ttl UInt8,
			tcp_flags String,
			payload String,
			ja4_raw String,
			ja4_application String,
			ja4_device String,
			ja4_os String,
			ja4_verified Bool,
			ja4_confidence UInt32,
			sni String,
			sni_service String
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

		err := rows.Scan(
			&packetID,
			&timestamp,
			&pkt.SrcIp,
			&pkt.DstIp,
			&pkt.SrcPort,
			&pkt.DstPort,
			&pkt.Protocol,
			&pkt.Length,
			&ttl,
			&pkt.TcpFlags,
			&pkt.Payload,
			&pkt.Ja4Raw,
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
		)
		if err != nil {
			continue
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

		err := rows.Scan(
			&packetID,
			&timestamp,
			&pkt.SrcIp,
			&pkt.DstIp,
			&pkt.SrcPort,
			&pkt.DstPort,
			&pkt.Protocol,
			&pkt.Length,
			&ttl,
			&pkt.TcpFlags,
			&pkt.Payload,
			&pkt.Ja4Raw,
			&pkt.Ja4Application,
			&pkt.Ja4Device,
			&pkt.Ja4Os,
			&ja4Verified,
			&ja4Confidence,
			&pkt.Sni,
			&pkt.SniService,
		)
		if err != nil {
			continue
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
			placeholders := strings.Repeat("?,", len(filter.Protocols))
			placeholders = placeholders[:len(placeholders)-1]
			conditions = append(conditions, fmt.Sprintf("protocol IN (%s)", placeholders))
			for _, p := range filter.Protocols {
				args = append(args, p)
			}
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
			conditions = append(conditions, "payload LIKE ?")
			args = append(args, "%"+filter.TextSearch+"%")
		}
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
        SELECT packet_id, timestamp, src_ip, dst_ip, src_port, dst_port, 
               protocol, length, ttl, tcp_flags, payload,
               ja4_raw, ja4_application, ja4_device, ja4_os, 
               ja4_verified, ja4_confidence, sni, sni_service
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
			protocol, length, ttl, tcp_flags, payload,
			ja4_raw, ja4_application, ja4_device, ja4_os,
			ja4_verified, ja4_confidence, sni, sni_service
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

		_, err = stmt.ExecContext(ctx,
			packetID,
			pkt.Timestamp,
			pkt.SrcIP,
			pkt.DstIP,
			pkt.SrcPort,
			pkt.DstPort,
			pkt.Protocol,
			pkt.Length,
			pkt.TTL,
			pkt.TCPFlags,
			payload,
			pkt.JA4Raw,
			pkt.JA4Application,
			pkt.JA4Device,
			pkt.JA4OS,
			pkt.JA4Verified,
			pkt.JA4Confidence,
			pkt.SNI,
			pkt.SNIService,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
