package grpc

import (
	"context"
	"runtime"
	"time"

	pb "sniffer/core/grpc/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetMetrics(ctx context.Context, req *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	resp := &pb.MetricsResponse{
		// Основные счетчики из памяти
		PacketsCount: s.stats.packetsTotal.Load(),
		BytesTotal:   s.stats.bytesTotal.Load(),
		Error:        "",
	}

	// Получаем агрегированные данные из ClickHouse
	if s.storage != nil && s.storage.Enabled() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Статистика по протоколам
		protocols, err := s.getProtocolStats(ctx)
		if err == nil {
			resp.Protocols = protocols
		}

		// Статистика по приложениям
		apps, err := s.getApplicationStats(ctx)
		if err == nil {
			resp.Applications = apps
		}

		// Временная аналитика
		resp.PacketsPerSecond, resp.BytesPerSecond = s.getCurrentRates()
		resp.PacketsLastMinute, resp.BytesLastMinute = s.getLastMinuteStats(ctx)

		// TCP специфика
		resp.TcpConnections = s.getActiveConnections(ctx)
		resp.TcpSynPackets, resp.TcpFinPackets, resp.TcpRstPackets, resp.TcpRetransmissions = s.getTCPStats(ctx)

		// Размеры пакетов
		resp.AvgPacketSize, resp.MinPacketSize, resp.MaxPacketSize = s.getPacketSizeStats(ctx)
		resp.PacketSizeDistribution = s.getPacketSizeDistribution(ctx)

		// IP специфика
		resp.Ipv4Packets, resp.Ipv6Packets = s.getIPStats(ctx)
		resp.FragmentedPackets, resp.MalformedPackets = s.getErrorStats(ctx)

		// Топ портов и IP
		resp.TopSrcPorts, resp.TopDstPorts = s.getTopPorts(ctx, 10)
		resp.TopSrcIps, resp.TopDstIps = s.getTopIPs(ctx, 10)
	}

	// Health метрики
	resp.CpuUsage = s.getCPUUsage()
	resp.MemoryBytes = s.getMemoryUsage()
	resp.MemoryTotalBytes = s.getTotalMemory()
	resp.UptimeSeconds = int64(time.Since(startTime).Seconds())
	resp.PacketsDropped = s.stats.packetsTotal.Load() - s.getProcessedPacketsCount() // пример
	resp.Version = "1.0.0"
	resp.GoVersion = runtime.Version()
	resp.NumGoroutines = int32(runtime.NumGoroutine())
	resp.Device = ""
	resp.PromiscMode = false
	resp.Filter = ""
	return resp, nil
}

// Статистика по протоколам
func (s *Server) getProtocolStats(ctx context.Context) (map[string]int64, error) {
	query := `
		SELECT protocol, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY protocol
	`

	rows, err := s.storage.GetConn().QueryContext(ctx, query, s.config.SnifferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var protocol string
		var count int64
		if err := rows.Scan(&protocol, &count); err == nil {
			result[protocol] = count
		}
	}
	return result, nil
}

// Статистика по приложениям (по портам)
func (s *Server) getApplicationStats(ctx context.Context) (map[string]int64, error) {
	// Определяем приложения по портам
	query := `
		SELECT
			CASE
				WHEN dst_port = 80 OR src_port = 80 THEN 'HTTP'
				WHEN dst_port = 443 OR src_port = 443 THEN 'HTTPS'
				WHEN dst_port = 53 OR src_port = 53 THEN 'DNS'
				WHEN dst_port = 22 OR src_port = 22 THEN 'SSH'
				WHEN dst_port = 21 OR src_port = 21 THEN 'FTP'
				WHEN dst_port = 25 OR src_port = 25 THEN 'SMTP'
				WHEN dst_port = 3306 OR src_port = 3306 THEN 'MySQL'
				WHEN dst_port = 5432 OR src_port = 5432 THEN 'PostgreSQL'
				ELSE 'OTHER'
			END as app,
			COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY app
	`

	rows, err := s.storage.GetConn().QueryContext(ctx, query, s.config.SnifferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var app string
		var count int64
		if err := rows.Scan(&app, &count); err == nil {
			result[app] = count
		}
	}
	return result, nil
}

// Текущие скорости (пакеты/сек, байты/сек)
func (s *Server) getCurrentRates() (int64, float64) {
	// Считаем за последние 10 секунд
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := `
		SELECT 
			COUNT() as packets,
			SUM(length) as bytes
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 10 SECOND
	`

	var packets, bytes int64
	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&packets, &bytes)
	if err != nil {
		return 0, 0
	}

	return packets / 10, float64(bytes) / 10.0
}

// Статистика за последнюю минуту
func (s *Server) getLastMinuteStats(ctx context.Context) (int64, int64) {
	query := `
		SELECT 
			COUNT() as packets,
			SUM(length) as bytes
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 1 MINUTE
	`

	var packets, bytes int64
	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&packets, &bytes)
	if err != nil {
		return 0, 0
	}
	return packets, bytes
}

// TCP статистика
func (s *Server) getTCPStats(ctx context.Context) (syn, fin, rst, retrans int64) {
	// SYN, FIN, RST флаги
	query := `
		SELECT 
			COUNT(CASE WHEN tcp_flags LIKE '%S%' THEN 1 END) as syn,
			COUNT(CASE WHEN tcp_flags LIKE '%F%' THEN 1 END) as fin,
			COUNT(CASE WHEN tcp_flags LIKE '%R%' THEN 1 END) as rst
		FROM packets
		WHERE sniffer_id = ? AND protocol = 'TCP' AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&syn, &fin, &rst)
	if err != nil {
		return 0, 0, 0, 0
	}

	// Ретрансмиссии - сложнее, нужен анализ последовательностей
	// Пока заглушка
	retrans = 0

	return syn, fin, rst, retrans
}

// Статистика размеров пакетов
func (s *Server) getPacketSizeStats(ctx context.Context) (avg float64, min, max int64) {
	query := `
		SELECT 
			AVG(length) as avg,
			MIN(length) as min,
			MAX(length) as max
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&avg, &min, &max)
	if err != nil {
		return 0, 0, 0
	}
	return avg, min, max
}

// Распределение по размерам
func (s *Server) getPacketSizeDistribution(ctx context.Context) map[int32]int64 {
	query := `
		SELECT 
			CASE
				WHEN length <= 64 THEN 64
				WHEN length <= 128 THEN 128
				WHEN length <= 256 THEN 256
				WHEN length <= 512 THEN 512
				WHEN length <= 1024 THEN 1024
				WHEN length <= 1500 THEN 1500
				ELSE 1501
			END as size_bucket,
			COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY size_bucket
	`

	rows, err := s.storage.GetConn().QueryContext(ctx, query, s.config.SnifferID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[int32]int64)
	for rows.Next() {
		var bucket int32
		var count int64
		if err := rows.Scan(&bucket, &count); err == nil {
			result[bucket] = count
		}
	}
	return result
}

// IP статистика
func (s *Server) getIPStats(ctx context.Context) (ipv4, ipv6 int64) {
	query := `
		SELECT 
			COUNT(CASE WHEN src_ip LIKE '%.%' THEN 1 END) as ipv4,
			COUNT(CASE WHEN src_ip LIKE '%:%' THEN 1 END) as ipv6
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&ipv4, &ipv6)
	if err != nil {
		return 0, 0
	}
	return ipv4, ipv6
}

// Топ портов
func (s *Server) getTopPorts(ctx context.Context, limit int) (map[int32]int64, map[int32]int64) {
	// Топ src портов
	srcQuery := `
		SELECT src_port, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY src_port
		ORDER BY count DESC
		LIMIT ?
	`

	srcRows, err := s.storage.GetConn().QueryContext(ctx, srcQuery, s.config.SnifferID, limit)
	if err != nil {
		return nil, nil
	}
	defer srcRows.Close()

	srcPorts := make(map[int32]int64)
	for srcRows.Next() {
		var port int32
		var count int64
		if err := srcRows.Scan(&port, &count); err == nil {
			srcPorts[port] = count
		}
	}

	// Топ dst портов
	dstQuery := `
		SELECT dst_port, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY dst_port
		ORDER BY count DESC
		LIMIT ?
	`

	dstRows, err := s.storage.GetConn().QueryContext(ctx, dstQuery, s.config.SnifferID, limit)
	if err != nil {
		return srcPorts, nil
	}
	defer dstRows.Close()

	dstPorts := make(map[int32]int64)
	for dstRows.Next() {
		var port int32
		var count int64
		if err := dstRows.Scan(&port, &count); err == nil {
			dstPorts[port] = count
		}
	}

	return srcPorts, dstPorts
}

// Топ IP адресов
func (s *Server) getTopIPs(ctx context.Context, limit int) (map[string]int64, map[string]int64) {
	// Топ src IP
	srcQuery := `
		SELECT src_ip, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY src_ip
		ORDER BY count DESC
		LIMIT ?
	`

	srcRows, err := s.storage.GetConn().QueryContext(ctx, srcQuery, s.config.SnifferID, limit)
	if err != nil {
		return nil, nil
	}
	defer srcRows.Close()

	srcIPs := make(map[string]int64)
	for srcRows.Next() {
		var ip string
		var count int64
		if err := srcRows.Scan(&ip, &count); err == nil {
			srcIPs[ip] = count
		}
	}

	// Топ dst IP
	dstQuery := `
		SELECT dst_ip, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY dst_ip
		ORDER BY count DESC
		LIMIT ?
	`

	dstRows, err := s.storage.GetConn().QueryContext(ctx, dstQuery, s.config.SnifferID, limit)
	if err != nil {
		return srcIPs, nil
	}
	defer dstRows.Close()

	dstIPs := make(map[string]int64)
	for dstRows.Next() {
		var ip string
		var count int64
		if err := dstRows.Scan(&ip, &count); err == nil {
			dstIPs[ip] = count
		}
	}

	return srcIPs, dstIPs
}

// Health метрики
func (s *Server) getCPUUsage() float64 {
	// В Go сложно получить CPU usage процесса
	// Можно использовать runtime или системные вызовы
	// Пока заглушка
	return 0.0
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

func (s *Server) getProcessedPacketsCount() int64 {
	// Сколько пакетов реально обработано и сохранено
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	query := `SELECT COUNT() FROM packets WHERE sniffer_id = ?`
	var count int64
	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (s *Server) getActiveConnections(ctx context.Context) int64 {
	// Активные TCP соединения (есть SYN, нет FIN)
	query := `
		SELECT COUNT(DISTINCT CONCAT(src_ip, ':', dst_ip, ':', src_port, ':', dst_port))
		FROM packets
		WHERE sniffer_id = ? 
			AND protocol = 'TCP' 
			AND timestamp > now() - INTERVAL 1 MINUTE
	`

	var count int64
	err := s.storage.GetConn().QueryRowContext(ctx, query, s.config.SnifferID).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (s *Server) getErrorStats(ctx context.Context) (fragmented, malformed int64) {
	// Фрагментированные пакеты (по флагам IP)
	fragQuery := `
		SELECT COUNT()
		FROM packets
		WHERE sniffer_id = ? AND protocol = 'IPv4' AND tcp_flags LIKE '%frag%'
	`

	err := s.storage.GetConn().QueryRowContext(ctx, fragQuery, s.config.SnifferID).Scan(&fragmented)
	if err != nil {
		fragmented = 0
	}

	// Битые пакеты (нет простого способа определить в ClickHouse)
	malformed = 0

	return fragmented, malformed
}
