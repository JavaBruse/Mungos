package clickhouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sniffer/core/logger"
	"sniffer/core/models"
	"time"

	"github.com/google/uuid"
)

type JA4JsonEntry struct {
	Application          string  `json:"application"`
	Library              *string `json:"library"`
	Device               *string `json:"device"`
	OS                   string  `json:"os"`
	UserAgentString      *string `json:"user_agent_string"`
	CertificateAuthority *string `json:"certificate_authority"`
	ObservationCount     int     `json:"observation_count"`
	Verified             bool    `json:"verified"`
	Notes                *string `json:"notes"`
	JA4Fingerprint       string  `json:"ja4_fingerprint"`
	JA4SFingerprint      *string `json:"ja4s_fingerprint"`
	JA4HFingerprint      *string `json:"ja4h_fingerprint"`
	JA4XFingerprint      *string `json:"ja4x_fingerprint"`
	JA4TFingerprint      *string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     *string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  *string `json:"ja4tscan_fingerprint"`
}

func createJA4Table(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS ja4_database (
			id String,
			fingerprint String,
			application String,
			library Nullable(String),
			device Nullable(String),
			os String,
			observation_count UInt32,
			verified Bool,
			fingerprint_type String
		) ENGINE = MergeTree()
		ORDER BY fingerprint
	`
	_, err := conn.Exec(query)
	return err
}

func (c *ClickHouseStorage) InitJA4Database(ctx context.Context) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}
	createJA4Table(c.conn)

	ja4FilePath := os.Getenv("JA4_DB_PATH")
	var count uint64
	err := c.conn.QueryRowContext(ctx, "SELECT COUNT() FROM ja4_database").Scan(&count)
	if err != nil {
		logger.Error("Failed to check JA4 DB count: %v", err)
	}

	if count > 0 {
		logger.Info("JA4 DB already loaded: %d entries", count)
		return nil
	}

	entries, err := c.loadEntries(ja4FilePath)
	if err != nil {
		return err
	}
	return c.saveJA4ToDB(ctx, entries)
}

func (c *ClickHouseStorage) loadEntries(path string) ([]JA4JsonEntry, error) {
	if path != "" {
		entries, err := c.loadFromFile(path)
		if err == nil {
			logger.Info("Loaded %d entries from file", len(entries))
			return entries, nil
		}
		logger.Info("No file found at %s", path)
	}
	return c.downloadFromAPI()
}

func (c *ClickHouseStorage) loadFromFile(path string) ([]JA4JsonEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var entries []JA4JsonEntry
	err = json.NewDecoder(file).Decode(&entries)
	return entries, err
}

func (c *ClickHouseStorage) downloadFromAPI() ([]JA4JsonEntry, error) {
	ja4APIURL := os.Getenv("JA4_DB_WEB_PATH")

	for {
		logger.Info("Downloading JA4 database from %s", ja4APIURL)

		client := &http.Client{
			Timeout: 0,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return nil
			},
		}

		resp, err := client.Get(ja4APIURL)
		if err != nil {
			logger.Error("Download failed: %v, retrying in 10 seconds...", err)
			time.Sleep(10 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			logger.Error("API returned %s, retrying in 10 seconds...", resp.Status)
			time.Sleep(10 * time.Second)
			continue
		}

		var entries []JA4JsonEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			logger.Error("Failed to decode JSON: %v, retrying...", err)
			time.Sleep(10 * time.Second)
			continue
		}

		logger.Info("Downloaded %d entries", len(entries))
		return entries, nil
	}
}

func (c *ClickHouseStorage) saveJA4ToDB(ctx context.Context, entries []JA4JsonEntry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ja4_database (id, fingerprint, application, library, device, os, observation_count, verified, fingerprint_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		id := uuid.New().String()
		application := e.Application
		if (application == "" || application == "null") && e.UserAgentString != nil && *e.UserAgentString != "" {
			application = *e.UserAgentString
		}
		if e.JA4Fingerprint != "" {
			stmt.ExecContext(ctx, id, e.JA4Fingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4")
		}
		if e.JA4HFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4HFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4h")
		}
		if e.JA4SFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4SFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4s")
		}

		if e.JA4XFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4XFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4x")
		}

		if e.JA4TFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4TFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4t")
		}

		if e.JA4TSFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4TSFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4ts")
		}

		if e.JA4TScanFingerprint != nil {
			stmt.ExecContext(ctx, id, *e.JA4TScanFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4r")
		}
	}

	return tx.Commit()
}

func (c *ClickHouseStorage) LookupJA4(ctx context.Context, fp string) (*models.Ja4Entry, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	var e models.Ja4Entry
	var lib, dev sql.NullString

	err := c.conn.QueryRowContext(ctx, `
		SELECT application, library, device, os, observation_count, verified
		FROM ja4_database WHERE fingerprint = ? LIMIT 1
	`, fp).Scan(&e.Application, &lib, &dev, &e.OS, &e.ObservationCount, &e.Verified)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		c.reconnect()
		return nil, err
	}

	if lib.Valid {
		e.Library = lib.String
	}
	if dev.Valid {
		e.Device = dev.String
	}
	return &e, nil
}

func (c *ClickHouseStorage) UpdateJA4Database(ctx context.Context) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	entries, err := c.downloadFromAPI()
	if err != nil {
		return err
	}

	if _, err := c.conn.ExecContext(ctx, "DROP TABLE IF EXISTS ja4_database"); err != nil {
		return err
	}

	if err := createJA4Table(c.conn); err != nil {
		return err
	}

	return c.saveJA4ToDB(ctx, entries)
}

// GetAllJA4Entries возвращает все записи из базы
func (c *ClickHouseStorage) GetAllJA4Entries(ctx context.Context) ([]models.Ja4Entry, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	rows, err := c.conn.QueryContext(ctx, `
        SELECT id, fingerprint, application, library, device, os, 
               observation_count, verified, fingerprint_type
        FROM ja4_database
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.Ja4Entry
	for rows.Next() {
		var e models.Ja4Entry
		var lib, dev sql.NullString

		err := rows.Scan(&e.ID, &e.Fingerprint, &e.Application, &lib, &dev,
			&e.OS, &e.ObservationCount, &e.Verified, &e.FingerprintType)
		if err != nil {
			return nil, err
		}

		if lib.Valid {
			e.Library = lib.String
		}
		if dev.Valid {
			e.Device = dev.String
		}

		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// SaveDBEntry сохраняет или обновляет запись по ID
func (c *ClickHouseStorage) SaveDBEntry(ctx context.Context, entry models.Ja4Entry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	// Если ID пустой - генерируем новый
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	// Проверяем существование по ID
	var exists uint64
	err := c.conn.QueryRowContext(ctx, "SELECT COUNT() FROM ja4_database WHERE id = ?", entry.ID).Scan(&exists)
	if err != nil {
		return err
	}

	if exists > 0 {
		// Обновляем существующую запись
		_, err = c.conn.ExecContext(ctx, `
			ALTER TABLE ja4_database UPDATE 
				fingerprint = ?, application = ?, library = ?, device = ?, 
				os = ?, observation_count = ?, verified = ?, fingerprint_type = ?
			WHERE id = ?
		`, entry.Fingerprint, entry.Application, entry.Library, entry.Device,
			entry.OS, entry.ObservationCount, entry.Verified, entry.FingerprintType, entry.ID)
	} else {
		// Вставляем новую запись
		_, err = c.conn.ExecContext(ctx, `
			INSERT INTO ja4_database (id, fingerprint, application, library, device, os, observation_count, verified, fingerprint_type)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, entry.ID, entry.Fingerprint, entry.Application, entry.Library,
			entry.Device, entry.OS, entry.ObservationCount, entry.Verified, entry.FingerprintType)
	}

	return err
}

// ReplaceDBEntries полная замена базы данными из DBEntry
func (c *ClickHouseStorage) ReplaceDBEntries(ctx context.Context, entries []models.Ja4Entry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	if _, err := c.conn.ExecContext(ctx, "TRUNCATE TABLE ja4_database"); err != nil {
		return err
	}

	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO ja4_database (id, fingerprint, application, library, device, os, observation_count, verified, fingerprint_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err := stmt.ExecContext(ctx, e.ID, e.Fingerprint, e.Application,
			e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, e.FingerprintType)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// DeleteDBEntry удаляет запись по ID
func (c *ClickHouseStorage) DeleteDBEntry(ctx context.Context, id string) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	_, err := c.conn.ExecContext(ctx, "ALTER TABLE ja4_database DELETE WHERE id = ?", id)
	return err
}
