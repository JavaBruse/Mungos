package grpc

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
)

type ClickHouseClientStorage struct {
	conn *sql.DB
}

func NewClickHouseClientStorage(host string, port int, user, password, db string) (*ClickHouseClientStorage, error) {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s", user, password, host, port, db)

	conn, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse not available: %w", err)
	}

	// Создаем таблицу для хранения клиентов (с приватным ключом)
	if err := createClientsTable(conn); err != nil {
		log.Printf("Failed to create clients table: %v", err)
	}

	log.Println("✅ ClickHouse client storage connected")
	return &ClickHouseClientStorage{conn: conn}, nil
}

func createClientsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sniffer_clients (
			client_id String,
			session_key String,
			master_key String,
			server_certificate String,
			server_private_key String,  -- ДОБАВЛЯЕМ поле для приватного ключа
			created_at DateTime
		) ENGINE = MergeTree()
		ORDER BY (client_id)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseClientStorage) SaveClient(ctx context.Context, data *ClientData) error {
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
	return err
}

func (c *ClickHouseClientStorage) GetClientBySession(ctx context.Context, sessionKey string) (*ClientData, error) {
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
		return nil, err
	}
	return &data, nil
}

func (c *ClickHouseClientStorage) GetClientByID(ctx context.Context, clientID string) (*ClientData, error) {
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
		return nil, err
	}
	return &data, nil
}

func (c *ClickHouseClientStorage) ClientExists(ctx context.Context) (bool, error) {
	query := `SELECT COUNT() FROM sniffer_clients`
	var count uint64
	err := c.conn.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (c *ClickHouseClientStorage) DeleteClient(ctx context.Context, sessionKey string) error {
	query := `ALTER TABLE sniffer_clients DELETE WHERE session_key = ?`
	_, err := c.conn.ExecContext(ctx, query, sessionKey)
	return err
}

func (c *ClickHouseClientStorage) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
