package server

import (
	"context"
	"time"

	pb "sniffer/core/grpc/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetMetrics(ctx context.Context, req *pb.AuthRequest) (*pb.MetricsResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	resp := &pb.MetricsResponse{
		PacketsCount: s.stats.packetsTotal.Load(),
		BytesTotal:   s.stats.bytesTotal.Load(),
		Error:        "",
	}

	if s.storage != nil && s.storage.Enabled() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Статистика по протоколам
		if protocols, err := s.storage.GetProtocolStats(ctx); err == nil {
			resp.Protocols = protocols
		}

		// Статистика по приложениям (топ 10)
		if ports, err := s.storage.GetWellKnownPortsStats(ctx); err == nil {
			resp.WellKnownPorts = ports
		}

		// Топ сервисов (топ 10)
		if services, err := s.storage.GetTopServices(ctx, 10); err == nil {
			resp.TopServices = services
		}

		// Топ сервисов по соединениям (топ 10)
		if servicesByConn, err := s.storage.GetTopServicesByConnections(ctx, 10); err == nil {
			resp.TopServicesByConnections = servicesByConn
		}

		// Временная аналитика (за 5 секунд)
		if packetsPerSec, bytesPerSec, err := s.storage.GetCurrentRates(ctx); err == nil {
			resp.PacketsPerSecond = packetsPerSec
			resp.BytesPerSecond = bytesPerSec
		}

		// TCP специфика
		if conns, err := s.storage.GetActiveConnections(ctx); err == nil {
			resp.TcpConnections = conns
		}

		if syn, fin, rst, err := s.storage.GetTCPStats(ctx); err == nil {
			resp.TcpSynPackets = syn
			resp.TcpFinPackets = fin
			resp.TcpRstPackets = rst
		}

		// Известные/неизвестные пакеты (общие)
		if known, err := s.storage.GetKnownPacketsCount(ctx); err == nil {
			resp.AllKnow = known
		}

		if unknown, err := s.storage.GetUnknownPacketsCount(ctx); err == nil {
			resp.AllUnknow = unknown
		}

		// Известные/неизвестные пакеты за 5 секунд
		if known5sec, unknown5sec, err := s.storage.GetKnownUnknown5Sec(ctx); err == nil {
			resp.KnownPackets_5Sec = known5sec
			resp.UnknownPackets_5Sec = unknown5sec
		}
	}

	return resp, nil
}
