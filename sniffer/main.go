//go:generate protoc --go_out=. --go-grpc_out=. proto/sniffer.proto
package main

import (
	"log"

	"sniffer/core/app"
	"sniffer/core/config"
)

func main() {
	cfg := config.Load()

	application, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}
