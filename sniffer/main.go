//go:generate protoc --go_out=. --go-grpc_out=. proto/sniffer.proto
package main

import (
	"log"
	"os"
	"time"

	"sniffer/core/app"
	"sniffer/core/config"
	"sniffer/core/logger"
	"sniffer/core/storage/memory"
)

func main() {
	if err := memory.InitOUIDatabase("/data/oui.txt"); err != nil {
		logger.Error("Failed to load OUI database: %v", err)
	}
	if tz := os.Getenv("TZ"); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			logger.Error("Invalid TZ %s, using local: %v", tz, err)
		} else {
			time.Local = loc
		}
	}

	cfg := config.Load()

	application, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}
