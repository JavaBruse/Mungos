package app

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sniffer/core/capture"
	"sniffer/core/config"
	"sniffer/core/grpc"
	"sniffer/core/storage"
)

type App struct {
	config     *config.Config
	sniffer    *capture.Sniffer
	fileLogger *storage.PacketLogger
	chStorage  *storage.ClickHouseStorage
	grpc       *grpc.Server
	packetChan chan *capture.Packet
	stopChan   chan struct{}
}

func New(cfg *config.Config) (*App, error) {
	sniffer := capture.NewSniffer(
		cfg.Device,
		cfg.Snaplen,
		cfg.Promisc,
		30*time.Second,
		cfg.BPFFilter,
		10000,
	)

	fileLogger, err := storage.NewPacketLogger(cfg.LogFile)
	if err != nil {
		log.Printf("File logger disabled: %v", err)
		fileLogger = nil
	}

	chStorage, _ := storage.NewClickHouseStorage(
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPass,
		cfg.DBName,
	)

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
		Storage:    chStorage,
	})

	return &App{
		config:     cfg,
		sniffer:    sniffer,
		fileLogger: fileLogger,
		chStorage:  chStorage,
		grpc:       grpcServer,
		packetChan: make(chan *capture.Packet, 500000), // УВЕЛИЧИЛИ ДО 500К
		stopChan:   make(chan struct{}),
	}, nil
}

func (a *App) Run() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Запускаем батчевый воркер
	go a.batchWorker()

	// gRPC
	go func() {
		if err := a.grpc.Start(); err != nil {
			log.Printf("gRPC error: %v", err)
		}
	}()

	// Сниффер
	go func() {
		if err := a.sniffer.Start(); err != nil {
			log.Printf("Sniffer error: %v", err)
		}
	}()

	// Обработка пакетов
	go func() {
		for pkt := range a.sniffer.Packets() {
			if a.fileLogger != nil {
				a.fileLogger.Write(pkt)
			}

			select {
			case a.packetChan <- pkt:
			default:
				log.Printf("Warning: packet channel full, dropping packet")
			}

			a.grpc.UpdateStats(pkt)
		}
	}()

	log.Println("App started")
	<-sigChan

	// Завершение работы
	close(a.stopChan)
	time.Sleep(2 * time.Second)

	a.sniffer.Stop()
	if a.fileLogger != nil {
		a.fileLogger.Close()
	}
	if a.chStorage != nil {
		a.chStorage.Close()
	}

	return nil
}

func (a *App) batchWorker() {
	batch := make([]*capture.Packet, 0, 5000)
	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case pkt := <-a.packetChan:
			batch = append(batch, pkt)
			if len(batch) >= 5000 {
				a.saveBatch(batch)
				batch = make([]*capture.Packet, 0, 5000)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.saveBatch(batch)
				batch = make([]*capture.Packet, 0, 5000)
			}
		}
	}
}

func (a *App) saveBatch(packets []*capture.Packet) {
	if a.chStorage == nil || !a.chStorage.Enabled() {
		return
	}

	if err := a.chStorage.SavePackets(packets, a.config.SnifferID); err != nil {
		log.Printf("Failed to save batch of %d packets: %v", len(packets), err)
	} else {
		log.Printf("Saved batch of %d packets", len(packets))
	}
}
