package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type SettingsData struct {
	BPFFilter string
	CreatedAt time.Time
}

func createSettingTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sniffer_settings (
			filters String,
			create_at DateTime
		) ENGINE = ReplacingMergeTree(create_at)
		ORDER BY create_at
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
			filters, create_at
		) VALUES (?, ?)
	`
	_, err := c.conn.ExecContext(ctx, query,
		data.BPFFilter,
		data.CreatedAt,
	)
	if err != nil {
		c.reconnect()
	}
	return err
}

func (c *ClickHouseStorage) GetSetting(ctx context.Context) (*SettingsData, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	query := `
		SELECT filters, create_at 
		FROM sniffer_settings 
		ORDER BY create_at DESC 
		LIMIT 1
	`

	var data SettingsData
	err := c.conn.QueryRowContext(ctx, query).Scan(
		&data.BPFFilter,
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

func (c *ClickHouseStorage) SettingsExists(ctx context.Context, clientID string) (bool, error) {
	if !c.ensureConnection() {
		return false, fmt.Errorf("ClickHouse not available")
	}

	query := `SELECT COUNT() FROM sniffer_settings`
	var count uint64
	err := c.conn.QueryRowContext(ctx, query, clientID).Scan(&count)
	if err != nil {
		c.reconnect()
		return false, err
	}
	return count > 0, nil
}
