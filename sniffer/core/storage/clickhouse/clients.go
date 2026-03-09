package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type ClientData struct {
	SessionKey        string
	ServerCertificate string
	ServerPrivateKey  string
	CreatedAt         time.Time
}

func createClientsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sniffer_clients (
			session_key String,
			server_certificate String,
			server_private_key String,
			created_at DateTime
		) ENGINE = MergeTree()
		ORDER BY (session_key)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) SaveClient(ctx context.Context, data *ClientData) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query := `
		INSERT INTO sniffer_clients (
			session_key, server_certificate, server_private_key, created_at
		) VALUES (?, ?, ?, ?)
	`
	_, err := c.conn.ExecContext(ctx, query,
		data.SessionKey,
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
			session_key, server_certificate, server_private_key, created_at
		FROM sniffer_clients 
		WHERE session_key = ?
		ORDER BY created_at
		LIMIT 1
	`

	var data ClientData
	err := c.conn.QueryRowContext(ctx, query, sessionKey).Scan(
		&data.SessionKey,
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

func (c *ClickHouseStorage) GetClient(ctx context.Context, clientID string) (*ClientData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `
		SELECT 
			session_key, server_certificate, server_private_key, created_at
		FROM sniffer_clients 
		ORDER BY created_at 
		LIMIT 1
	`

	var data ClientData
	err := c.conn.QueryRowContext(ctx, query, clientID).Scan(
		&data.SessionKey,
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
