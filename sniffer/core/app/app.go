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
	"sniffer/core/method"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
)

type App struct {
	config     *config.Config
	sniffer    *capture.Sniffer
	chStorage  *clickhouse.ClickHouseStorage
	grpc       *server.Server
	packetChan chan *models.Packet
	stopChan   chan struct{}
}

func New(cfg *config.Config) (*App, error) {
	chStorage, _ := clickhouse.NewClickHouseStorage(
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPass,
		cfg.DBName,
	)

	capture.InitRuleCache(chStorage)
	method.GetSNIProcessor(chStorage)

	filter := loadFilterFromStorage(chStorage)

	sniffer := capture.NewSniffer(
		cfg.Device,
		cfg.Snaplen,
		cfg.Promisc,
		30*time.Second,
		filter,
		10000,
		chStorage,
	)

	app := &App{
		config:     cfg,
		sniffer:    sniffer,
		chStorage:  chStorage,
		packetChan: make(chan *models.Packet, 500000),
		stopChan:   make(chan struct{}),
	}

	grpcServer := server.NewServer(&server.Config{
		MasterKey:  cfg.MasterKey,
		GRPCPort:   cfg.GRPCPort,
		DBHost:     cfg.DBHost,
		DBPort:     cfg.DBPort,
		DBUser:     cfg.DBUser,
		DBPass:     cfg.DBPass,
		DBName:     cfg.DBName,
		DBProtocol: cfg.DBProtocol,
		Storage:    chStorage,
	})

	app.grpc = grpcServer

	return app, nil
}

func loadFilterFromStorage(chStorage *clickhouse.ClickHouseStorage) string {
	if chStorage == nil || !chStorage.Enabled() {
		logger.Info("Storage not available, using empty filter")
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	settings, err := chStorage.GetSetting(ctx)
	if err != nil {
		logger.Error("Failed to get settings: %v", err)
		return ""
	}

	if settings == nil {
		logger.Info("No settings in DB, saving empty filter")
		settingsData := &models.SettingsData{
			BPFFilter: config.Load().BPFFilter,
			CreatedAt: time.Now(),
		}
		if err := chStorage.SaveSettings(ctx, settingsData); err != nil {
			logger.Error("Failed to save initial settings: %v", err)
		}
		return config.Load().BPFFilter
	}

	logger.Info("Settings loaded from DB: %s", settings.BPFFilter)
	return settings.BPFFilter
}

func (a *App) Run() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go a.batchWorker()

	if a.chStorage != nil && a.chStorage.Enabled() {
		ctx := context.Background()
		if err := a.chStorage.InitJA4Database(ctx); err != nil {
			logger.Error("Failed to init JA4 DB: %v", err)
		}
	}

	go func() { _ = a.grpc.Start() }()
	go func() { _ = a.sniffer.Start() }()

	// Просто передаем пакеты в канал для сохранения
	for pkt := range a.sniffer.Packets() {
		select {
		case a.packetChan <- pkt:
		default:
			logger.Warn("packet channel full, dropping packet")
		}
		a.grpc.UpdateStats(pkt)
	}

	logger.Info("App started")
	<-sigChan

	close(a.stopChan)
	time.Sleep(2 * time.Second)
	a.sniffer.Stop()
	if a.chStorage != nil {
		a.chStorage.Close()
	}
	return nil
}

func (a *App) batchWorker() {
	batch := make([]*models.Packet, 0, 5000)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case pkt := <-a.packetChan:
			batch = append(batch, pkt)
			if len(batch) >= 5000 {
				a.saveBatch(batch)
				batch = make([]*models.Packet, 0, 5000)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.saveBatch(batch)
				batch = make([]*models.Packet, 0, 5000)
			}
		case <-a.stopChan:
			return
		}
	}
}

func (a *App) saveBatch(packets []*models.Packet) {
	if a.chStorage == nil || !a.chStorage.Enabled() {
		return
	}

	if err := a.chStorage.SavePackets(packets); err != nil {
		logger.Error("Failed to save batch of %d packets: %v", len(packets), err)
	} else {
		logger.Info("Saved batch of %d packets", len(packets))
	}
}
