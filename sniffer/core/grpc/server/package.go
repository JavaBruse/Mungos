package server

import (
	"context"

	"sniffer/core/capture"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"
	"sniffer/core/models"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetFilteredPackage(req *pb.PackageFilterRequest, stream pb.SnifferService_GetFilteredPackageServer) error {
	if !s.checkAuth(stream.Context(), req.GetSessionKey()) {
		return status.Error(codes.Unauthenticated, "invalid session")
	}
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

func (s *Server) GetConnectionInsight(ctx context.Context, req *pb.ConnectionInsightRequest) (*pb.ConnectionInsight, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("GetConnectionInsight: packet_id=%s", req.GetPacketId())

	if s.storage == nil || !s.storage.Enabled() {
		return nil, status.Error(codes.Internal, "storage not available")
	}

	insight, err := s.storage.GetConnectionInsightByPacket(ctx, req.GetPacketId())
	if err != nil {
		logger.Error("Failed to get connection insight: %v", err)
		return nil, status.Error(codes.Internal, "failed to get connection insight")
	}

	return convertToProtoConnectionInsight(insight), nil
}

func convertToProtoConnectionInsight(insight *models.ConnectionInsight) *pb.ConnectionInsight {
	if insight == nil {
		return nil
	}

	localPorts := make([]uint32, len(insight.LocalPorts))
	for i, port := range insight.LocalPorts {
		localPorts[i] = uint32(port)
	}

	ja4Candidates := make([]*pb.JA4Candidate, len(insight.JA4Candidates))
	for i, cand := range insight.JA4Candidates {
		ja4Candidates[i] = &pb.JA4Candidate{
			Id:          cand.ID,
			Fingerprint: cand.Fingerprint,
			Application: cand.Application,
			Device:      cand.Device,
			Os:          cand.OS,
			Count:       cand.Count,
			Confidence:  int32(cand.Confidence),
			Hop:         int32(cand.Hop),
		}
	}

	sniCandidates := make([]*pb.SNICandidate, len(insight.SNICandidates))
	for i, cand := range insight.SNICandidates {
		sniCandidates[i] = &pb.SNICandidate{
			Id:         cand.ID,
			Sni:        cand.SNI,
			Service:    cand.Service,
			Count:      cand.Count,
			Confidence: int32(cand.Confidence),
			Hop:        int32(cand.Hop),
		}
	}

	return &pb.ConnectionInsight{
		LocalIp:           insight.LocalIP,
		LocalPorts:        localPorts,
		RemoteIp:          insight.RemoteIP,
		RemotePort:        uint32(insight.RemotePort),
		TotalPackets:      insight.TotalPackets,
		TotalBytes:        insight.TotalBytes,
		FirstPacketTime:   insight.FirstPacketTime,
		LastPacketTime:    insight.LastPacketTime,
		SynCount:          insight.SynCount,
		FinCount:          insight.FinCount,
		RstCount:          insight.RstCount,
		IdentifiedPackets: insight.IdentifiedPackets,
		Ja4Candidates:     ja4Candidates,
		SniCandidates:     sniCandidates,
	}
}

func (s *Server) UpdateConnectionInsight(ctx context.Context, req *pb.UpdateConnectionInsightRequest) (*pb.UpdateConnectionInsightResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	if s.storage == nil || !s.storage.Enabled() {
		return nil, status.Error(codes.Internal, "storage not available")
	}

	remoteIP, remotePort, ja4Entry, sniEntry, err := s.storage.UpdateConnectionInsight(ctx, req.GetPacketId(), req.GetJa4EntryId(), req.GetSniEntryId())
	if err != nil {
		logger.Error("Failed to update connection insight: %v", err)
		return nil, status.Error(codes.Internal, "failed to update")
	}

	if ruleCache := capture.GetRuleCache(); ruleCache != nil {
		ruleCache.Add(ctx, remoteIP, remotePort, ja4Entry, sniEntry)
	}
	return &pb.UpdateConnectionInsightResponse{Success: true}, nil
}
