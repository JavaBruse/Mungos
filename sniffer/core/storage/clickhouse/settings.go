package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
)

func createSettingTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sniffer_settings (
			client_id String,
			port_filter Array(Int32),
			ip_filter Array(String),
			create_at DateTime
		) ENGINE = ReplacingMergeTree(create_at)
		ORDER BY (client_id)
	`

	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) SaveSettings(ctx context.Context, data *SettingsData) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	query := `
		INSERT INTO sniffer_settings (
			client_id, port_filter, ip_filter, create_at
		) VALUES (?, ?, ?, ?)
	`
	_, err := c.conn.ExecContext(ctx, query,
		data.ClientID,
		data.PortFilter,
		data.IPFilter,
		data.CreatedAt,
	)
	if err != nil {
		c.reconnect()
	}
	return err
}

func (c *ClickHouseStorage) GetSetting(ctx context.Context, client_id string) (*SettingsData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `
		SELECT client_id, port_filter, ip_filter, create_at 
		FROM sniffer_settings 
		WHERE client_id = ?
		ORDER BY create_at DESC 
		LIMIT 1
	`

	var data SettingsData
	err := c.conn.QueryRowContext(ctx, query, client_id).Scan(
		&data.ClientID,
		&data.PortFilter,
		&data.IPFilter,
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
