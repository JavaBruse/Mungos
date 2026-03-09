package clickhouse

import (
	"context"
	"fmt"
)

// GetProtocolStats - статистика по протоколам
func (c *ClickHouseStorage) GetProtocolStats(ctx context.Context, snifferID string) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT protocol, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY protocol
	`

	rows, err := c.conn.QueryContext(ctx, query, snifferID)
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

// GetApplicationStats - статистика по приложениям
func (c *ClickHouseStorage) GetApplicationStats(ctx context.Context, snifferID string) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

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

	rows, err := c.conn.QueryContext(ctx, query, snifferID)
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

// GetCurrentRates - текущие скорости (пакеты/сек, байты/сек)
func (c *ClickHouseStorage) GetCurrentRates(ctx context.Context, snifferID string) (int64, float64, error) {
	if !c.ensureConnection() {
		return 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT() as packets,
			SUM(length) as bytes
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 10 SECOND
	`

	var packets, bytes int64
	err := c.conn.QueryRowContext(ctx, query, snifferID).Scan(&packets, &bytes)
	if err != nil {
		return 0, 0, err
	}

	return packets / 10, float64(bytes) / 10.0, nil
}

// GetLastMinuteStats - статистика за последнюю минуту
func (c *ClickHouseStorage) GetLastMinuteStats(ctx context.Context, snifferID string) (int64, int64, error) {
	if !c.ensureConnection() {
		return 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT() as packets,
			SUM(length) as bytes
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 1 MINUTE
	`

	var packets, bytes int64
	err := c.conn.QueryRowContext(ctx, query, snifferID).Scan(&packets, &bytes)
	if err != nil {
		return 0, 0, err
	}
	return packets, bytes, nil
}

// GetTCPStats - TCP статистика
func (c *ClickHouseStorage) GetTCPStats(ctx context.Context, snifferID string) (syn, fin, rst int64, err error) {
	if !c.ensureConnection() {
		return 0, 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT(CASE WHEN tcp_flags LIKE '%S%' THEN 1 END) as syn,
			COUNT(CASE WHEN tcp_flags LIKE '%F%' THEN 1 END) as fin,
			COUNT(CASE WHEN tcp_flags LIKE '%R%' THEN 1 END) as rst
		FROM packets
		WHERE sniffer_id = ? AND protocol = 'TCP' AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err = c.conn.QueryRowContext(ctx, query, snifferID).Scan(&syn, &fin, &rst)
	return syn, fin, rst, err
}

// GetPacketSizeStats - статистика размеров пакетов
func (c *ClickHouseStorage) GetPacketSizeStats(ctx context.Context, snifferID string) (avg float64, min, max int64, err error) {
	if !c.ensureConnection() {
		return 0, 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			AVG(length) as avg,
			MIN(length) as min,
			MAX(length) as max
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err = c.conn.QueryRowContext(ctx, query, snifferID).Scan(&avg, &min, &max)
	return avg, min, max, err
}

// GetPacketSizeDistribution - распределение по размерам
func (c *ClickHouseStorage) GetPacketSizeDistribution(ctx context.Context, snifferID string) (map[int32]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

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

	rows, err := c.conn.QueryContext(ctx, query, snifferID)
	if err != nil {
		return nil, err
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
	return result, nil
}

// GetIPStats - IP статистика
func (c *ClickHouseStorage) GetIPStats(ctx context.Context, snifferID string) (ipv4, ipv6 int64, err error) {
	if !c.ensureConnection() {
		return 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT(CASE WHEN src_ip LIKE '%.%' THEN 1 END) as ipv4,
			COUNT(CASE WHEN src_ip LIKE '%:%' THEN 1 END) as ipv6
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err = c.conn.QueryRowContext(ctx, query, snifferID).Scan(&ipv4, &ipv6)
	return ipv4, ipv6, err
}

// GetTopPorts - топ портов
func (c *ClickHouseStorage) GetTopPorts(ctx context.Context, snifferID string, limit int) (srcPorts, dstPorts map[int32]int64, err error) {
	if !c.ensureConnection() {
		return nil, nil, fmt.Errorf("storage not available")
	}

	// Топ src портов
	srcQuery := `
		SELECT src_port, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY src_port
		ORDER BY count DESC
		LIMIT ?
	`

	srcRows, err := c.conn.QueryContext(ctx, srcQuery, snifferID, limit)
	if err != nil {
		return nil, nil, err
	}
	defer srcRows.Close()

	srcPorts = make(map[int32]int64)
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

	dstRows, err := c.conn.QueryContext(ctx, dstQuery, snifferID, limit)
	if err != nil {
		return srcPorts, nil, err
	}
	defer dstRows.Close()

	dstPorts = make(map[int32]int64)
	for dstRows.Next() {
		var port int32
		var count int64
		if err := dstRows.Scan(&port, &count); err == nil {
			dstPorts[port] = count
		}
	}

	return srcPorts, dstPorts, nil
}

// GetTopIPs - топ IP адресов
func (c *ClickHouseStorage) GetTopIPs(ctx context.Context, snifferID string, limit int) (srcIPs, dstIPs map[string]int64, err error) {
	if !c.ensureConnection() {
		return nil, nil, fmt.Errorf("storage not available")
	}

	// Топ src IP
	srcQuery := `
		SELECT src_ip, COUNT() as count
		FROM packets
		WHERE sniffer_id = ? AND timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY src_ip
		ORDER BY count DESC
		LIMIT ?
	`

	srcRows, err := c.conn.QueryContext(ctx, srcQuery, snifferID, limit)
	if err != nil {
		return nil, nil, err
	}
	defer srcRows.Close()

	srcIPs = make(map[string]int64)
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

	dstRows, err := c.conn.QueryContext(ctx, dstQuery, snifferID, limit)
	if err != nil {
		return srcIPs, nil, err
	}
	defer dstRows.Close()

	dstIPs = make(map[string]int64)
	for dstRows.Next() {
		var ip string
		var count int64
		if err := dstRows.Scan(&ip, &count); err == nil {
			dstIPs[ip] = count
		}
	}

	return srcIPs, dstIPs, nil
}

// GetProcessedPacketsCount - количество обработанных пакетов
func (c *ClickHouseStorage) GetProcessedPacketsCount(ctx context.Context, snifferID string) (int64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	query := `SELECT COUNT() FROM packets WHERE sniffer_id = ?`
	var count int64
	err := c.conn.QueryRowContext(ctx, query, snifferID).Scan(&count)
	return count, err
}

// GetActiveConnections - активные TCP соединения
func (c *ClickHouseStorage) GetActiveConnections(ctx context.Context, snifferID string) (int64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT COUNT(DISTINCT CONCAT(src_ip, ':', dst_ip, ':', src_port, ':', dst_port))
		FROM packets
		WHERE sniffer_id = ? 
			AND protocol = 'TCP' 
			AND timestamp > now() - INTERVAL 1 MINUTE
	`

	var count int64
	err := c.conn.QueryRowContext(ctx, query, snifferID).Scan(&count)
	return count, err
}

// GetErrorStats - статистика ошибок
func (c *ClickHouseStorage) GetErrorStats(ctx context.Context, snifferID string) (fragmented int64, err error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	fragQuery := `
		SELECT COUNT()
		FROM packets
		WHERE sniffer_id = ? AND protocol = 'IPv4' AND tcp_flags LIKE '%frag%'
	`

	err = c.conn.QueryRowContext(ctx, fragQuery, snifferID).Scan(&fragmented)
	return fragmented, err
}
