package server

import (
	"context"

	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetFilteredPackage(req *pb.PackageFilterRequest, stream pb.SnifferService_GetFilteredPackageServer) error {
	logger.Info("GetFilteredTraffic called for sniffer: %s", s.config.SnifferID)
	logger.Info("GetFilteredTraffic: limit=%d, offset=%d", req.GetLimit(), req.GetOffset())

	// Проверяем storage
	if s.storage == nil {
		logger.Info("storage is nil")
		return status.Error(codes.Internal, "storage not available")
	}

	// Получаем пакеты
	packets, err := s.storage.GetPackets(stream.Context(), req.GetFilter(),
		req.GetLimit(), req.GetOffset(), s.config.SnifferID)
	if err != nil {
		logger.Error("Failed to get packets: %v", err)
		return err
	}

	logger.Info("Found %d packets", len(packets))
	for _, pkt := range packets {
		if err := stream.Send(pkt); err != nil {
			logger.Error("Failed to send packet: %v", err)
			return err
		}
	}
	logger.Info("Successfully sent %d packets for offset=%d", len(packets), req.GetOffset())

	return nil
}

func (s *Server) GetPacketPayload(ctx context.Context, req *pb.PayloadRequest) (*pb.PayloadResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("GetPacketPayload: packet_id=%s", req.GetPacketId())

	if s.storage == nil || !s.storage.Enabled() {
		return nil, status.Error(codes.Internal, "storage not available")
	}

	// Получаем payload из ClickHouse по packet_id
	payload, err := s.storage.GetPacketPayload(ctx, req.GetPacketId())
	if err != nil {
		logger.Error("Failed to get payload: %v", err)
		return nil, status.Error(codes.Internal, "failed to get payload")
	}

	return &pb.PayloadResponse{Payload: payload}, nil
}
