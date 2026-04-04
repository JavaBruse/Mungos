package clickhouse

import (
	"context"
	"fmt"
)

// GetTopServices - топ сервисов по SNI/JA4
func (c *ClickHouseStorage) GetTopServices(ctx context.Context, limit int) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT COALESCE(sni_service, ja4_application) as service, COUNT() as count
		FROM packets
		WHERE (sni != '' OR ja4_raw != '')
		GROUP BY service
		ORDER BY count DESC
		LIMIT ?
	`

	rows, err := c.conn.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var service string
		var count int64
		if err := rows.Scan(&service, &count); err == nil {
			result[service] = count
		}
	}
	return result, nil
}

// GetTopServicesByConnections - топ сервисов по количеству уникальных соединений
func (c *ClickHouseStorage) GetTopServicesByConnections(ctx context.Context, limit int) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COALESCE(sni_service, ja4_application) as service,
			COUNT(DISTINCT CONCAT(src_ip, ':', src_port, ':', dst_ip, ':', dst_port)) as connections
		FROM packets
		WHERE (sni != '' OR ja4_raw != '')
		GROUP BY service
		ORDER BY connections DESC
		LIMIT ?
	`

	rows, err := c.conn.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var service string
		var connections int64
		if err := rows.Scan(&service, &connections); err == nil {
			result[service] = connections
		}
	}
	return result, nil
}

// GetKnownUnknown5Sec - известные и неизвестные пакеты за последние 5 секунд
func (c *ClickHouseStorage) GetKnownUnknown5Sec(ctx context.Context) (known, unknown int64, err error) {
	if !c.ensureConnection() {
		return 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT(CASE WHEN (ja4_raw != '' OR sni != '') THEN 1 END) as known,
			COUNT(CASE WHEN (ja4_raw = '' AND sni = '') THEN 1 END) as unknown
		FROM packets
		WHERE timestamp > now() - INTERVAL 5 SECOND
	`

	err = c.conn.QueryRowContext(ctx, query).Scan(&known, &unknown)
	return known, unknown, err
}

// GetProtocolStats - статистика по протоколам
func (c *ClickHouseStorage) GetProtocolStats(ctx context.Context) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT protocol, COUNT() as count
		FROM packets
		WHERE timestamp > now() - INTERVAL 5 MINUTE
		GROUP BY protocol
	`

	rows, err := c.conn.QueryContext(ctx, query)
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

// GetWellKnownPortsStats - статистика по известным портам за последние 5 минут
func (c *ClickHouseStorage) GetWellKnownPortsStats(ctx context.Context) (map[string]int64, error) {
	if !c.ensureConnection() {
		return nil, fmt.Errorf("storage not available")
	}

	query := `
		SELECT
			CASE
				WHEN dst_port = 80 OR src_port = 80 THEN 'HTTP (80)'
				WHEN dst_port = 443 OR src_port = 443 THEN 'HTTPS (443)'
				WHEN dst_port = 53 OR src_port = 53 THEN 'DNS (53)'
				WHEN dst_port = 22 OR src_port = 22 THEN 'SSH (22)'
				WHEN dst_port = 21 OR src_port = 21 THEN 'FTP (21)'
				WHEN dst_port = 25 OR src_port = 25 THEN 'SMTP (25)'
				WHEN dst_port = 3306 OR src_port = 3306 THEN 'MySQL (3306)'
				WHEN dst_port = 5432 OR src_port = 5432 THEN 'PostgreSQL (5432)'
				ELSE 'OTHER'
			END as port_name,
			COUNT() as count
		FROM packets
		WHERE timestamp > now() - INTERVAL 5 SECOND
		GROUP BY port_name
		ORDER BY count DESC
	`

	rows, err := c.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var portName string
		var count int64
		if err := rows.Scan(&portName, &count); err == nil {
			result[portName] = count
		}
	}
	return result, nil
}

// GetCurrentRates - текущие скорости (пакеты/сек, байты/сек) за последние 5 секунд
func (c *ClickHouseStorage) GetCurrentRates(ctx context.Context) (int64, float64, error) {
	if !c.ensureConnection() {
		return 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT() as packets,
			SUM(length) as bytes
		FROM packets
		WHERE timestamp > now() - INTERVAL 5 SECOND
	`

	var packets, bytes int64
	err := c.conn.QueryRowContext(ctx, query).Scan(&packets, &bytes)
	if err != nil {
		return 0, 0, err
	}

	return packets, float64(bytes), nil
}

// GetTCPStats - TCP статистика
func (c *ClickHouseStorage) GetTCPStats(ctx context.Context) (syn, fin, rst int64, err error) {
	if !c.ensureConnection() {
		return 0, 0, 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT 
			COUNT(CASE WHEN tcp_flags LIKE '%S%' THEN 1 END) as syn,
			COUNT(CASE WHEN tcp_flags LIKE '%F%' THEN 1 END) as fin,
			COUNT(CASE WHEN tcp_flags LIKE '%R%' THEN 1 END) as rst
		FROM packets
		WHERE protocol = 'TCP' AND timestamp > now() - INTERVAL 5 MINUTE
	`

	err = c.conn.QueryRowContext(ctx, query).Scan(&syn, &fin, &rst)
	return syn, fin, rst, err
}

// GetActiveConnections - активные TCP соединения
func (c *ClickHouseStorage) GetActiveConnections(ctx context.Context) (int64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT COUNT(DISTINCT CONCAT(src_ip, ':', dst_ip, ':', src_port, ':', dst_port))
		FROM packets
		WHERE protocol = 'TCP' 
			AND timestamp > now() - INTERVAL 1 MINUTE
	`

	var count int64
	err := c.conn.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

// GetKnownPacketsCount - количество известных пакетов (где хотя бы одно поле заполнено)
func (c *ClickHouseStorage) GetKnownPacketsCount(ctx context.Context) (int64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT COUNT()
		FROM packets
		WHERE (ja4_raw != '' OR sni != '')
	`

	var count int64
	err := c.conn.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

// GetUnknownPacketsCount - количество неизвестных пакетов (где оба поля пустые)
func (c *ClickHouseStorage) GetUnknownPacketsCount(ctx context.Context) (int64, error) {
	if !c.ensureConnection() {
		return 0, fmt.Errorf("storage not available")
	}

	query := `
		SELECT COUNT()
		FROM packets
		WHERE (ja4_raw = '' AND sni = '')
	`

	var count int64
	err := c.conn.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}
