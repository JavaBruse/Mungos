package server

import (
	"context"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"
	"sniffer/core/storage/clickhouse"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetSettings(ctx context.Context, req *pb.SettingRequest) (*pb.SettingResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	if s.storage == nil || !s.storage.Enabled() {
		return nil, status.Error(codes.Internal, "storage not available")
	}

	settings, err := s.storage.GetSetting(ctx)
	if err != nil {
		logger.Error("Failed to get settings: %v", err)
		return nil, status.Error(codes.Internal, "failed to get settings")
	}

	if settings == nil {
		return &pb.SettingResponse{
			Filters:   []string{},
			Timestamp: time.Now().Unix(),
		}, nil
	}

	return &pb.SettingResponse{
		Filters:   settings.BPFFilter,
		Timestamp: settings.CreatedAt.Unix(),
	}, nil
}

func (s *Server) SetSettings(ctx context.Context, req *pb.SettingRequest) (*pb.SettingResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	if s.storage == nil || !s.storage.Enabled() {
		return nil, status.Error(codes.Internal, "storage not available")
	}

	settingsData := &clickhouse.SettingsData{
		BPFFilter: req.GetFilters(),
		CreatedAt: time.Now(),
	}

	if err := s.storage.SaveSettings(ctx, settingsData); err != nil {
		logger.Error("Failed to save settings: %v", err)
		return nil, status.Error(codes.Internal, "failed to save settings")
	}

	if s.app != nil {
		s.app.UpdateSnifferFilter(req.GetFilters())
	}

	logger.Info("Settings saved")

	return &pb.SettingResponse{
		Filters:   req.GetFilters(),
		Timestamp: settingsData.CreatedAt.Unix(),
	}, nil
}
