package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"sniffer/core/capture"

	_ "github.com/ClickHouse/clickhouse-go/v2"
)

type ClickHouseStorage struct {
	conn    *sql.DB
	enabled bool
}

func NewClickHouseStorage(host string, port int, user, password, db string) (*ClickHouseStorage, error) {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s", user, password, host, port, db)

	conn, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(time.Minute)

	// Проверяем соединение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		log.Printf("ClickHouse not available: %v", err)
		return &ClickHouseStorage{enabled: false}, nil
	}

	// Создаем таблицу
	if err := createTable(conn); err != nil {
		log.Printf("Failed to create table: %v", err)
	}

	log.Println("✅ ClickHouse connected")
	return &ClickHouseStorage{
		conn:    conn,
		enabled: true,
	}, nil
}

func createTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS packets (
			timestamp DateTime64(9) CODEC(Delta, ZSTD),
			sniffer_id String,
			src_ip String,
			dst_ip String,
			src_port UInt16,
			dst_port UInt16,
			protocol String,
			length UInt32,
			ttl UInt8,
			tcp_flags String,
			payload String
		) ENGINE = MergeTree()
		ORDER BY (timestamp, src_ip, dst_ip)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) SavePacket(pkt *capture.Packet, snifferID string) error {
	if !c.enabled || c.conn == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Ограничиваем payload для ClickHouse
	payload := string(pkt.Payload)
	if len(payload) > 10000 {
		payload = payload[:10000]
	}

	query := `
		INSERT INTO packets (
			timestamp, sniffer_id, src_ip, dst_ip, src_port, dst_port,
			protocol, length, ttl, tcp_flags, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := c.conn.ExecContext(ctx, query,
		pkt.Timestamp,
		snifferID,
		pkt.SrcIP,
		pkt.DstIP,
		pkt.SrcPort,
		pkt.DstPort,
		pkt.Protocol,
		pkt.Length,
		pkt.TTL,
		pkt.TCPFlags,
		payload,
	)

	if err != nil {
		log.Printf("Failed to save to ClickHouse: %v", err)
	}
	return err
}

func (c *ClickHouseStorage) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *ClickHouseStorage) Enabled() bool {
	return c.enabled
}
