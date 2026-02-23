package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"sniffer/core/capture"
	pb "sniffer/core/grpc/proto"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

type ClickHouseStorage struct {
	conn     *sql.DB
	enabled  bool
	host     string
	port     int
	user     string
	password string
	db       string
}

func NewClickHouseStorage(host string, port int, user, password, db string) (*ClickHouseStorage, error) {
	storage := &ClickHouseStorage{
		host:     host,
		port:     port,
		user:     user,
		password: password,
		db:       db,
	}

	// Первое подключение
	if err := storage.connect(); err != nil {
		log.Printf("Initial ClickHouse connection failed: %v", err)
		return storage, nil
	}

	// Создаем таблицы
	createPacketsTable(storage.conn)
	createClientsTable(storage.conn)

	log.Println("✅ ClickHouse connected")
	return storage, nil
}

func (c *ClickHouseStorage) connect() error {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s", c.user, c.password, c.host, c.port, c.db)

	conn, err := sql.Open("clickhouse", dsn)
	if err != nil {
		c.enabled = false
		return err
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		c.enabled = false
		return err
	}

	c.conn = conn
	c.enabled = true
	return nil
}

func (c *ClickHouseStorage) reconnect() {
	if c.enabled && c.conn != nil {
		// Проверим текущее соединение
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := c.conn.PingContext(ctx)
		cancel()
		if err == nil {
			return // Все ок
		}
		log.Printf("ClickHouse connection lost: %v", err)
	}

	log.Println("🔄 Reconnecting to ClickHouse...")

	for i := 0; i < 30; i++ {
		if err := c.connect(); err == nil {
			log.Println("✅ Reconnected to ClickHouse")
			return
		}
		time.Sleep(2 * time.Second)
	}

	log.Println("❌ Failed to reconnect to ClickHouse")
	c.enabled = false
}

func (c *ClickHouseStorage) ensureConnection() bool {
	if !c.enabled || c.conn == nil {
		c.reconnect()
	}
	return c.enabled && c.conn != nil
}

func createPacketsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS packets (
			packet_id String,
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

func createClientsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sniffer_clients (
			client_id String,
			session_key String,
			master_key String,
			server_certificate String,
			server_private_key String,
			created_at DateTime
		) ENGINE = MergeTree()
		ORDER BY (client_id)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) SavePackets(packets []*capture.Packet, snifferID string) error {
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
			packet_id, timestamp, sniffer_id, src_ip, dst_ip, src_port, dst_port,
			protocol, length, ttl, tcp_flags, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			return err
		}
	}

	return tx.Commit()
}

func (c *ClickHouseStorage) GetPackets(ctx context.Context, filter *pb.FilterExpression,
	limit, offset int32, snifferID string) ([]*pb.TrafficPacket, error) {

	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query, args := buildFilterQuery(filter, limit, offset, snifferID)

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
		)
		if err != nil {
			continue
		}

		pkt.Timestamp = timestamp.UnixNano()
		pkt.PacketId = packetID
		pkt.Ttl = int32(ttl)
		packets = append(packets, &pkt)
	}

	return packets, nil
}

func (c *ClickHouseStorage) StreamPackets(ctx context.Context, filter *pb.FilterExpression,
	snifferID string, sendFunc func(*pb.TrafficPacket) error) error {

	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query, args := buildFilterQuery(filter, 10000, 0, snifferID)

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
		)
		if err != nil {
			continue
		}

		pkt.Timestamp = timestamp.UnixNano()
		pkt.PacketId = packetID
		pkt.Ttl = int32(ttl)

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

func buildFilterQuery(filter *pb.FilterExpression, limit, offset int32, snifferID string) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "sniffer_id = ?")
	args = append(args, snifferID)

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
			conditions = append(conditions, "(src_port IN (?) OR dst_port IN (?))")
			args = append(args, filter.Ports, filter.Ports)
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

	query := fmt.Sprintf(`
        SELECT packet_id, timestamp, src_ip, dst_ip, src_port, dst_port, 
               protocol, length, ttl, tcp_flags, payload
        FROM packets
        WHERE %s
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    `, strings.Join(conditions, " AND "))

	args = append(args, limit, offset)

	return query, args
}

func (c *ClickHouseStorage) SaveClient(ctx context.Context, data *ClientData) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query := `
		INSERT INTO sniffer_clients (
			client_id, session_key, master_key, server_certificate, server_private_key, created_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := c.conn.ExecContext(ctx, query,
		data.ClientID,
		data.SessionKey,
		data.MasterKey,
		data.ServerCertificate,
		data.ServerPrivateKey,
		data.CreatedAt,
	)
	if err != nil {
		c.reconnect()
	}
	return err
}

func (c *ClickHouseStorage) GetClientBySession(ctx context.Context, sessionKey string) (*ClientData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `
		SELECT 
			client_id, session_key, master_key, server_certificate, server_private_key, created_at
		FROM sniffer_clients 
		WHERE session_key = ? 
		LIMIT 1
	`

	var data ClientData
	err := c.conn.QueryRowContext(ctx, query, sessionKey).Scan(
		&data.ClientID,
		&data.SessionKey,
		&data.MasterKey,
		&data.ServerCertificate,
		&data.ServerPrivateKey,
		&data.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		c.reconnect()
		return nil, err
	}
	return &data, nil
}

func (c *ClickHouseStorage) GetClientByID(ctx context.Context, clientID string) (*ClientData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `
		SELECT 
			client_id, session_key, master_key, server_certificate, server_private_key, created_at
		FROM sniffer_clients 
		WHERE client_id = ? 
		LIMIT 1
	`

	var data ClientData
	err := c.conn.QueryRowContext(ctx, query, clientID).Scan(
		&data.ClientID,
		&data.SessionKey,
		&data.MasterKey,
		&data.ServerCertificate,
		&data.ServerPrivateKey,
		&data.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		c.reconnect()
		return nil, err
	}
	return &data, nil
}

func (c *ClickHouseStorage) ClientExists(ctx context.Context) (bool, error) {
	if !c.ensureConnection() {
		return false, fmt.Errorf("ClickHouse not available")
	}

	query := `SELECT COUNT() FROM sniffer_clients`
	var count uint64
	err := c.conn.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		c.reconnect()
		return false, err
	}
	return count > 0, nil
}

func (c *ClickHouseStorage) DeleteClient(ctx context.Context, sessionKey string) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query := `ALTER TABLE sniffer_clients DELETE WHERE session_key = ?`
	_, err := c.conn.ExecContext(ctx, query, sessionKey)
	if err != nil {
		c.reconnect()
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

type ClientData struct {
	ClientID          string
	SessionKey        string
	MasterKey         string
	ServerCertificate string
	ServerPrivateKey  string
	CreatedAt         time.Time
}
