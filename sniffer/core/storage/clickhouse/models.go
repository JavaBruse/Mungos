package clickhouse

import (
	"database/sql"
	"time"
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

type ClientData struct {
	ClientID          string
	SessionKey        string
	MasterKey         string
	ServerCertificate string
	ServerPrivateKey  string
	CreatedAt         time.Time
}

type SettingsData struct {
	ClientID   string
	PortFilter []int32
	IPFilter   []string
	CreatedAt  time.Time
}
