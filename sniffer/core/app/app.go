package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sniffer/core/capture"
	"sniffer/core/config"
	"sniffer/core/grpc/server"
	"sniffer/core/logger"

	"sniffer/core/storage/clickhouse"
)

type App struct {
	config     *config.Config
	sniffer    *capture.Sniffer
	chStorage  *clickhouse.ClickHouseStorage
	grpc       *server.Server
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

	chStorage, _ := clickhouse.NewClickHouseStorage(
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPass,
		cfg.DBName,
	)

	if chStorage != nil && chStorage.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		settings, err := chStorage.GetSetting(ctx)
		if err != nil {
			logger.Error("Failed to get settings: %v", err)
		} else if settings == nil {
			settingsData := &clickhouse.SettingsData{
				BPFFilter: cfg.BPFFilter,
				CreatedAt: time.Now(),
			}
			if err := chStorage.SaveSettings(ctx, settingsData); err != nil {
				logger.Error("Failed to save initial settings: %v", err)
			} else {
				logger.Info("Initial settings saved for %s: %v", cfg.SnifferID, cfg.BPFFilter)
				if len(cfg.BPFFilter) > 0 {
					bpfFilter := sniffer.BuildBPFFilter(cfg.BPFFilter)
					sniffer.UpdateFilter(bpfFilter)
				}
			}
		} else {
			logger.Info("Settings loaded for %s", cfg.SnifferID)
			if len(settings.BPFFilter) > 0 {
				bpfFilter := sniffer.BuildBPFFilter(settings.BPFFilter)
				sniffer.UpdateFilter(bpfFilter)
			}
		}
	} else {
		if len(cfg.BPFFilter) > 0 {
			bpfFilter := sniffer.BuildBPFFilter(cfg.BPFFilter)
			sniffer.UpdateFilter(bpfFilter)
		}
	}

	grpcServer := server.NewServer(&server.Config{
		MasterKey:  cfg.MasterKey,
		SnifferID:  cfg.SnifferID,
		GRPCPort:   cfg.GRPCPort,
		DBHost:     cfg.DBHost,
		DBPort:     cfg.DBPort,
		DBUser:     cfg.DBUser,
		DBPass:     cfg.DBPass,
		DBName:     cfg.DBName,
		DBProtocol: cfg.DBProtocol,
		Storage:    chStorage,
	})

	return &App{
		config:     cfg,
		sniffer:    sniffer,
		chStorage:  chStorage,
		grpc:       grpcServer,
		packetChan: make(chan *capture.Packet, 500000),
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
			logger.Error("gRPC error: %v", err)
		}
	}()

	// Сниффер
	go func() {
		if err := a.sniffer.Start(); err != nil {
			logger.Error("Sniffer error: %v", err)
		}
	}()

	// Обработка пакетов
	go func() {
		for pkt := range a.sniffer.Packets() {
			select {
			case a.packetChan <- pkt:
			default:
				logger.Warn("packet channel full, dropping packet")
			}

			a.grpc.UpdateStats(pkt)
		}
	}()

	logger.Info("App started")
	<-sigChan

	// Завершение работы
	close(a.stopChan)
	time.Sleep(2 * time.Second)

	a.sniffer.Stop()
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
		logger.Error("Failed to save batch of %d packets: %v", len(packets), err)
	} else {
		logger.Info("Saved batch of %d packets", len(packets))
	}
}

func (a *App) UpdateSnifferFilter(filters []string) {
	if a.sniffer != nil {
		bpfFilter := a.sniffer.BuildBPFFilter(filters)
		a.sniffer.UpdateFilter(bpfFilter)
		logger.Info("Sniffer filter updated")
	}
}
