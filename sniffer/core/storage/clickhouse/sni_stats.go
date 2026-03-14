package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type SNIStat struct {
	Service         string
	SNI             string
	OccurrenceCount int
	FirstSeen       time.Time
	LastSeen        time.Time
}

func createSNIStatsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sni_stats (
			service String,
			sni String,
			occurrence_count UInt64,
			first_seen DateTime,
			last_seen DateTime
		) ENGINE = SummingMergeTree()
		ORDER BY (service, sni)
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) UpdateSNIStat(ctx context.Context, service, sni string) error {
	if !c.ensureConnection() {
		return fmt.Errorf("clickhouse not available")
	}

	query := `
		INSERT INTO sni_stats (service, sni, occurrence_count, first_seen, last_seen)
		VALUES (?, ?, 1, now(), now())
	`
	_, err := c.conn.ExecContext(ctx, query, service, sni)
	return err
}

func (c *ClickHouseStorage) GetSNIStats(ctx context.Context, service string) (map[string]int, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("clickhouse not available")
	}

	query := `
		SELECT sni, SUM(occurrence_count) as count
		FROM sni_stats
		WHERE service = ?
		GROUP BY sni
	`

	rows, err := c.conn.QueryContext(ctx, query, service)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var sni string
		var count int
		if err := rows.Scan(&sni, &count); err == nil {
			result[sni] = count
		}
	}
	return result, nil
}

func (c *ClickHouseStorage) GetAllServices(ctx context.Context) ([]string, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("clickhouse not available")
	}

	query := `SELECT DISTINCT service FROM sni_stats`
	rows, err := c.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []string
	for rows.Next() {
		var service string
		if err := rows.Scan(&service); err == nil {
			services = append(services, service)
		}
	}
	return services, nil
}

// Получить вероятность P(SNI|Service)
func (c *ClickHouseStorage) GetSNIProbability(ctx context.Context, service, sni string) (float64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("clickhouse not available")
	}

	query := `
		SELECT 
			SUM(if(sni = ?, occurrence_count, 0)) / SUM(occurrence_count) as prob
		FROM sni_stats
		WHERE service = ?
	`
	var prob float64
	err := c.conn.QueryRowContext(ctx, query, sni, service).Scan(&prob)
	return prob, err
}
