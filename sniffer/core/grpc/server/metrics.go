package server

import (
	"context"
	"runtime"
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

	// Получаем агрегированные данные из ClickHouse
	if s.storage != nil && s.storage.Enabled() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Статистика по протоколам
		if protocols, err := s.storage.GetProtocolStats(ctx, s.config.SnifferID); err == nil {
			resp.Protocols = protocols
		}

		// Статистика по приложениям
		if apps, err := s.storage.GetApplicationStats(ctx, s.config.SnifferID); err == nil {
			resp.Applications = apps
		}

		// Временная аналитика
		if packetsPerSec, bytesPerSec, err := s.storage.GetCurrentRates(ctx, s.config.SnifferID); err == nil {
			resp.PacketsPerSecond = packetsPerSec
			resp.BytesPerSecond = bytesPerSec
		}

		if packetsMin, bytesMin, err := s.storage.GetLastMinuteStats(ctx, s.config.SnifferID); err == nil {
			resp.PacketsLastMinute = packetsMin
			resp.BytesLastMinute = bytesMin
		}

		// TCP специфика
		if conns, err := s.storage.GetActiveConnections(ctx, s.config.SnifferID); err == nil {
			resp.TcpConnections = conns
		}

		if syn, fin, rst, err := s.storage.GetTCPStats(ctx, s.config.SnifferID); err == nil {
			resp.TcpSynPackets = syn
			resp.TcpFinPackets = fin
			resp.TcpRstPackets = rst
			// Ретрансмиссии пока заглушка
			resp.TcpRetransmissions = 0
		}

		// Размеры пакетов
		if avg, min, max, err := s.storage.GetPacketSizeStats(ctx, s.config.SnifferID); err == nil {
			resp.AvgPacketSize = avg
			resp.MinPacketSize = min
			resp.MaxPacketSize = max
		}

		if dist, err := s.storage.GetPacketSizeDistribution(ctx, s.config.SnifferID); err == nil {
			resp.PacketSizeDistribution = dist
		}

		// IP специфика
		if ipv4, ipv6, err := s.storage.GetIPStats(ctx, s.config.SnifferID); err == nil {
			resp.Ipv4Packets = ipv4
			resp.Ipv6Packets = ipv6
		}

		if frag, err := s.storage.GetErrorStats(ctx, s.config.SnifferID); err == nil {
			resp.FragmentedPackets = frag
			resp.MalformedPackets = 0
		}

		// Топ портов и IP
		if srcPorts, dstPorts, err := s.storage.GetTopPorts(ctx, s.config.SnifferID, 10); err == nil {
			resp.TopSrcPorts = srcPorts
			resp.TopDstPorts = dstPorts
		}

		if srcIPs, dstIPs, err := s.storage.GetTopIPs(ctx, s.config.SnifferID, 10); err == nil {
			resp.TopSrcIps = srcIPs
			resp.TopDstIps = dstIPs
		}

		if known, err := s.GetKnownPacketsCount(ctx, s.config.SnifferID); err == nil {
			resp.AllKnow = known
		}

		if unknown, err := s.GetUnknownPacketsCount(ctx, s.config.SnifferID); err == nil {
			resp.AllUnknow = unknown
		}
	}

	// Health метрики (не из БД)
	resp.CpuUsage = 0 // заглушка
	resp.MemoryBytes = s.getMemoryUsage()
	resp.MemoryTotalBytes = s.getTotalMemory()
	resp.UptimeSeconds = int64(time.Since(startTime).Seconds())

	if count, err := s.storage.GetProcessedPacketsCount(ctx, s.config.SnifferID); err == nil {
		resp.PacketsDropped = s.stats.packetsTotal.Load() - count
	}

	resp.Version = "1.0.0"
	resp.GoVersion = runtime.Version()
	resp.NumGoroutines = int32(runtime.NumGoroutine())
	resp.Device = ""
	resp.PromiscMode = false
	resp.Filter = ""

	return resp, nil
}

func (s *Server) getMemoryUsage() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Alloc)
}

func (s *Server) getTotalMemory() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.TotalAlloc)
}

func (s *Server) GetKnownPacketsCount(ctx context.Context, snifferID string) (int64, error) {
	if s.storage == nil || !s.storage.Enabled() {
		return 0, nil
	}
	return s.storage.GetKnownPacketsCount(ctx, snifferID)
}

func (s *Server) GetUnknownPacketsCount(ctx context.Context, snifferID string) (int64, error) {
	if s.storage == nil || !s.storage.Enabled() {
		return 0, nil
	}
	return s.storage.GetUnknownPacketsCount(ctx, snifferID)
}
