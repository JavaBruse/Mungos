package config

import (
	"os"
	"sniffer/core/logger"
	"strconv"
	"strings"
)

type Config struct {
	Device     string
	Snaplen    int
	Promisc    bool
	BPFFilter  []string
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
}

func Load() *Config {
	cfg := &Config{
		Device:     getEnv("SNIFFER_DEVICE", ""),
		Snaplen:    getEnvAsInt("SNIFFER_SNAPLEN", 0),
		Promisc:    getEnvAsBool("SNIFFER_PROMISC", false),
		BPFFilter:  getEnvAsStringSlice("SNIFFER_FILTERS", []string{}),
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

func getEnvAsStringSlice(key string, defaultVal []string) []string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		result = append(result, strings.TrimSpace(p))
	}
	logger.Info("filter: %v", result)

	return result
}
