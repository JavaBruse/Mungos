package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"sniffer/core/logger"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
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

func (c *ClickHouseStorage) GetConn() *sql.DB {
	return c.conn
}

func NewClickHouseStorage(host string, port int, user, password, db string) (*ClickHouseStorage, error) {
	storage := &ClickHouseStorage{
		host:     host,
		port:     port,
		user:     user,
		password: password,
		db:       db,
	}

	for {
		if err := storage.connect(); err == nil {
			createPacketsTable(storage.conn)
			createClientsTable(storage.conn)
			createSettingTable(storage.conn)
			createJA4Table(storage.conn)
			createSNIStatsTable(storage.conn)
			logger.Info("ClickHouse connected")
			return storage, nil
		}
		logger.Info("Waiting for ClickHouse...")
		time.Sleep(2 * time.Second)
	}
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
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := c.conn.PingContext(ctx)
		cancel()
		if err == nil {
			return
		}
		logger.Info("ClickHouse connection lost: %v", err)
	}

	logger.Info("Reconnecting to ClickHouse...")

	for i := 0; i < 30; i++ {
		if err := c.connect(); err == nil {
			logger.Info("Reconnected to ClickHouse")
			return
		}
		time.Sleep(2 * time.Second)
	}

	logger.Error("Failed to reconnect to ClickHouse")
	c.enabled = false
}

func (c *ClickHouseStorage) ensureConnection() bool {
	if !c.enabled || c.conn == nil {
		c.reconnect()
	}
	return c.enabled && c.conn != nil
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
