package app

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"sniffer/core/capture"
	"sniffer/core/config"
	"sniffer/core/grpc"
	"sniffer/core/storage"
)

type App struct {
	config  *config.Config
	sniffer *capture.Sniffer
	logger  *storage.PacketLogger
	grpc    *grpc.Server
}

func New(cfg *config.Config) (*App, error) {
	sniffer := capture.NewSniffer(
		cfg.Device,
		cfg.Snaplen,
		cfg.Promisc,
		0,
		cfg.BPFFilter,
		10000,
	)

	logger, err := storage.NewPacketLogger(cfg.LogFile)
	if err != nil {
		return nil, err
	}

	grpcServer := grpc.NewServer(&grpc.Config{
		MasterKey:  cfg.MasterKey,
		SnifferID:  cfg.SnifferID,
		GRPCPort:   cfg.GRPCPort,
		DBHost:     cfg.DBHost,
		DBPort:     cfg.DBPort,
		DBUser:     cfg.DBUser,
		DBPass:     cfg.DBPass,
		DBName:     cfg.DBName,
		DBProtocol: cfg.DBProtocol,
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
	})

	return &App{
		config:  cfg,
		sniffer: sniffer,
		logger:  logger,
		grpc:    grpcServer,
	}, nil
}

func (a *App) Run() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := a.grpc.Start(); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	go func() {
		if err := a.sniffer.Start(); err != nil {
			log.Printf("sniffer error: %v", err)
		}
	}()

	go func() {
		for pkt := range a.sniffer.Packets() {
			a.logger.Write(pkt)
			a.grpc.UpdateStats(pkt)
		}
	}()

	<-sigChan
	a.sniffer.Stop()
	a.logger.Close()
	log.Println("App stopped")
	return nil
}
