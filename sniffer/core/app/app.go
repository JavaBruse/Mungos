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
	packetChan chan *capture.Packet // Добавить
	stopChan   chan struct{}        // Добавить
}

func New(cfg *config.Config) (*App, error) {
	// Сниффер
	sniffer := capture.NewSniffer(
		cfg.Device,
		cfg.Snaplen,
		cfg.Promisc,
		30*time.Second,
		cfg.BPFFilter,
		10000,
	)

	var clientStorage grpc.ClientStorage
	if cfg.DBHost != "" {
		var err error
		clientStorage, err = grpc.NewClickHouseClientStorage(
			cfg.DBHost,
			cfg.DBPort,
			cfg.DBUser,
			cfg.DBPass,
			cfg.DBName,
		)
		if err != nil {
			log.Printf("Client storage not available: %v", err)
		}
	}

	// Файловый логгер
	fileLogger, err := storage.NewPacketLogger(cfg.LogFile)
	if err != nil {
		log.Printf("File logger disabled: %v", err)
		fileLogger = nil
	}

	// ClickHouse
	chStorage, _ := storage.NewClickHouseStorage(
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPass,
		cfg.DBName,
	)

	// gRPC сервер
	grpcServer := grpc.NewServer(&grpc.Config{
		MasterKey:     cfg.MasterKey,
		SnifferID:     cfg.SnifferID,
		GRPCPort:      cfg.GRPCPort,
		DBHost:        cfg.DBHost,
		DBPort:        cfg.DBPort,
		DBUser:        cfg.DBUser,
		DBPass:        cfg.DBPass,
		DBName:        cfg.DBName,
		DBProtocol:    cfg.DBProtocol,
		CertFile:      cfg.CertFile,
		KeyFile:       cfg.KeyFile,
		ClientStorage: clientStorage,
	})

	return &App{
		config:     cfg,
		sniffer:    sniffer,
		fileLogger: fileLogger,
		chStorage:  chStorage,
		grpc:       grpcServer,
		packetChan: make(chan *capture.Packet, 10000), // Буфер 10000 пакетов
		stopChan:   make(chan struct{}),
	}, nil
}

func (a *App) Run() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Запускаем воркеры для ClickHouse (3 штуки)
	for i := 0; i < 3; i++ {
		go a.clickhouseWorker(i)
	}

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

	// Обработка пакетов - теперь просто кидаем в канал
	go func() {
		for pkt := range a.sniffer.Packets() {
			// В файл (быстро, оставляем синхронно)
			if a.fileLogger != nil {
				a.fileLogger.Write(pkt)
			}

			// В канал для ClickHouse
			select {
			case a.packetChan <- pkt:
			default:
				log.Printf("Warning: packet channel full, dropping packet")
			}

			// Статистика
			a.grpc.UpdateStats(pkt)
		}
	}()

	log.Println("App started")
	<-sigChan

	// Сигнал остановки воркерам
	close(a.stopChan)

	// Даем время сохранить оставшиеся пакеты
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

// Добавить новый метод
func (a *App) clickhouseWorker(workerID int) {
	log.Printf("ClickHouse worker %d started", workerID)

	for {
		select {
		case <-a.stopChan:
			log.Printf("ClickHouse worker %d stopped", workerID)
			return
		case pkt := <-a.packetChan:
			if a.chStorage != nil && a.chStorage.Enabled() {
				// Сохраняем синхронно (без go)
				if err := a.chStorage.SavePacket(pkt, a.config.SnifferID); err != nil {
					// Логируем только реальные ошибки, не "connection reset"
					if err.Error() != "connection reset by peer" {
						log.Printf("Worker %d failed to save: %v", workerID, err)
					}
				}
			}
		}
	}
}
