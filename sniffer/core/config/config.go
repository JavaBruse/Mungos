package config

import (
	"os"
	"strconv"
)

type Config struct {
	Device     string
	Snaplen    int
	Promisc    bool
	BPFFilter  string
	LogFile    string
	GRPCPort   int
	MasterKey  string
	SnifferID  string
	DBType     string
	DBHost     string
	DBPort     int
	DBUser     string
	DBPass     string
	DBName     string
	DBProtocol string
	CertFile   string
	KeyFile    string
}

func Load() *Config {
	cfg := &Config{
		Device:     getEnv("SNIFFER_DEVICE", ""),
		Snaplen:    getEnvAsInt("SNIFFER_SNAPLEN", 0),
		Promisc:    getEnvAsBool("SNIFFER_PROMISC", false),
		BPFFilter:  getEnv("SNIFFER_FILTER", ""),
		LogFile:    getEnv("SNIFFER_LOG", ""),
		GRPCPort:   getEnvAsInt("SNIFFER_GRPC_PORT", 0),
		MasterKey:  getEnv("DEFAULT_MASTER_KEY", ""),
		SnifferID:  getEnv("SNIFFER_ID", ""),
		DBType:     getEnv("DB_TYPE", ""),
		DBHost:     getEnv("DB_HOST", ""),
		DBPort:     getEnvAsInt("DB_PORT", 0),
		DBUser:     getEnv("DB_USER", ""),
		DBPass:     getEnv("DB_PASS", ""),
		DBName:     getEnv("DB_NAME", ""),
		DBProtocol: getEnv("DB_PROTOCOL", ""),
		CertFile:   "/app/certs/sniffer.crt",
		KeyFile:    "/app/certs/sniffer.key",
	}
	return cfg
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}
