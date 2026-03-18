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
)

func createJA4Table(conn *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS ja4_database (
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

func (c *ClickHouseStorage) loadEntries(path string) ([]models.JA4DBEntry, error) {
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

func (c *ClickHouseStorage) loadFromFile(path string) ([]models.JA4DBEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var entries []models.JA4DBEntry
	err = json.NewDecoder(file).Decode(&entries)
	return entries, err
}

func (c *ClickHouseStorage) downloadFromAPI() ([]models.JA4DBEntry, error) {
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

		var entries []models.JA4DBEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			logger.Error("Failed to decode JSON: %v, retrying...", err)
			time.Sleep(10 * time.Second)
			continue
		}

		logger.Info("Downloaded %d entries", len(entries))
		return entries, nil
	}
}

func (c *ClickHouseStorage) saveJA4ToDB(ctx context.Context, entries []models.JA4DBEntry) error {
	if !c.ensureConnection() {
		return fmt.Errorf("ClickHouse not available")
	}

	tx, err := c.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ja4_database (fingerprint, application, library, device, os, observation_count, verified, fingerprint_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		application := e.Application
		if (application == "" || application == "null") && e.UserAgentString != nil && *e.UserAgentString != "" {
			application = *e.UserAgentString
		}
		if e.JA4Fingerprint != "" {
			stmt.ExecContext(ctx, e.JA4Fingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4")
		}
		if e.JA4HFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4HFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4h")
		}
		if e.JA4SFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4SFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4s")
		}

		if e.JA4XFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4XFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4x")
		}

		if e.JA4TFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4TFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4t")
		}

		if e.JA4TSFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4TSFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4ts")
		}

		if e.JA4TScanFingerprint != nil {
			stmt.ExecContext(ctx, *e.JA4TScanFingerprint, application, e.Library, e.Device, e.OS, e.ObservationCount, e.Verified, "ja4r")
		}
	}

	return tx.Commit()
}

func (c *ClickHouseStorage) LookupJA4(ctx context.Context, fp string) (*models.JA4DBEntry, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("ClickHouse not available")
	}

	var e models.JA4DBEntry
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
		e.Library = &lib.String
	}
	if dev.Valid {
		e.Device = &dev.String
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
