//go:generate protoc --go_out=. --go-grpc_out=. proto/sniffer.proto
package main

import (
	"log"
	"os"
	"time"

	"sniffer/core/app"
	"sniffer/core/config"
)

func main() {
	if tz := os.Getenv("TZ"); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			log.Printf("Invalid TZ %s, using local: %v", tz, err)
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
