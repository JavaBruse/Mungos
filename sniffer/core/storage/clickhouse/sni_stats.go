package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"sniffer/core/models"
	"time"

	"github.com/google/uuid"
)

func createSNIStatsTable(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS sni_stats (
			id String,
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

// GetSNIEntry находит существующую запись SNI и возвращает её ID
func (c *ClickHouseStorage) GetSNIEntry(ctx context.Context, service, sni string) (*models.SNIEntry, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("clickhouse not available")
	}

	var entry models.SNIEntry

	err := c.conn.QueryRowContext(ctx, `
		SELECT id, service, sni, occurrence_count, first_seen, last_seen
		FROM sni_stats
		WHERE service = ? AND sni = ?
		LIMIT 1
	`, service, sni).Scan(
		&entry.ID,
		&entry.Service,
		&entry.SNI,
		&entry.OccurrenceCount,
		&entry.FirstSeen,
		&entry.LastSeen,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (c *ClickHouseStorage) UpdateSNIStat(ctx context.Context, service, sni string) error {
	if !c.ensureConnection() {
		return fmt.Errorf("clickhouse not available")
	}
	existing, err := c.GetSNIEntry(ctx, service, sni)
	if err != nil {
		return err
	}

	id := uuid.New().String()
	firstSeen := time.Now()

	if existing != nil {
		id = existing.ID
		firstSeen = existing.FirstSeen
	}

	query := `
		INSERT INTO sni_stats (id, service, sni, occurrence_count, first_seen, last_seen)
		VALUES (?, ?, ?, 1, ?, now())
	`
	_, err = c.conn.ExecContext(ctx, query, id, service, sni, firstSeen)
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

// ReplaceSNIDatabase - полная замена SNI базы данными извне
func (c *ClickHouseStorage) ReplaceSNIDatabase(ctx context.Context, entries []models.SNIEntry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("clickhouse not available")
	}

	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "TRUNCATE TABLE sni_stats"); err != nil {
		return err
	}

	for _, entry := range entries {
		_, err := tx.ExecContext(ctx, `
            INSERT INTO sni_stats (id, service, sni, occurrence_count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        `, entry.ID, entry.Service, entry.SNI, entry.OccurrenceCount, entry.FirstSeen, entry.LastSeen)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetAllSNIEntries - получить все записи SNI базы
func (c *ClickHouseStorage) GetAllSNIEntries(ctx context.Context) ([]models.SNIEntry, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("clickhouse not available")
	}

	rows, err := c.conn.QueryContext(ctx, `
        SELECT id, service, sni, occurrence_count, first_seen, last_seen
        FROM sni_stats
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.SNIEntry
	for rows.Next() {
		var entry models.SNIEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Service,
			&entry.SNI,
			&entry.OccurrenceCount,
			&entry.FirstSeen,
			&entry.LastSeen,
		)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
