package method

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	utls "github.com/refraction-networking/utls"
)

func ProcessJA4(packet *models.Packet, tcp *layers.TCP, db *clickhouse.ClickHouseStorage) *models.Packet {
	if packet == nil || tcp == nil {
		return packet
	}

	packet.JA4Raw = computeJA4WithUTLS(tcp.Payload)

	if packet.JA4Raw != "" && db != nil && db.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		if entry, err := db.LookupJA4(ctx, packet.JA4Raw); err == nil && entry != nil {
			packet.JA4Application = entry.Application
			packet.JA4OS = entry.OS
			packet.JA4Verified = entry.Verified
			packet.JA4Confidence = entry.ObservationCount
			if entry.Device != nil {
				packet.JA4Device = *entry.Device
			}
		}
	}

	return packet
}

// computeJA4WithUTLS - вычисляет JA4 отпечаток используя utls.Fingerprinter
func computeJA4WithUTLS(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}

	// Используем Fingerprinter для разбора ClientHello
	fp := &utls.Fingerprinter{}
	spec, err := fp.FingerprintClientHello(payload)
	if err != nil {
		return ""
	}

	// Версию TLS нужно получать из первого байта payload, а не из spec
	// так как в spec она может быть в другом поле
	tlsVersion := getTLSVersionFromPayload(payload)
	protocol := "t"

	// Cipher suites (первые 2 группы, отсортированные)
	ciphers := getCipherString(spec.CipherSuites)

	// Расширения
	extensions := getExtensionsString(spec.Extensions)

	// Signature algorithms
	sigAlgos := getSignatureAlgosString(spec.Extensions)

	return strings.Join([]string{
		protocol + tlsVersion,
		ciphers,
		extensions,
		sigAlgos,
	}, "_")
}

// getTLSVersionFromPayload получает версию TLS напрямую из payload
func getTLSVersionFromPayload(payload []byte) string {
	if len(payload) < 5 {
		return "00"
	}

	// В TLS ClientHello версия находится в байтах [1:3]
	if payload[0] != 0x16 { // Не handshake
		return "00"
	}

	if len(payload) < 5 {
		return "00"
	}

	// major version
	if payload[1] == 0x03 {
		switch payload[2] {
		case 0x01:
			return "10" // TLS 1.0
		case 0x02:
			return "11" // TLS 1.1
		case 0x03:
			return "12" // TLS 1.2
		case 0x04:
			return "13" // TLS 1.3
		}
	}

	return "00"
}

func getCipherString(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "00000"
	}

	// Берем первые 2 (или сколько есть)
	count := 2
	if len(ciphers) < 2 {
		count = len(ciphers)
	}

	// Сортируем как требует JA4
	sorted := make([]uint16, count)
	copy(sorted, ciphers[:count])
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Формируем строку для хеша
	parts := make([]string, count)
	for i, c := range sorted {
		parts[i] = strconv.FormatUint(uint64(c), 16)
	}

	hash := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(hash[:])[:5]
}

// getExtensionsString получает типы расширений через рефлексию
func getExtensionsString(extensions []utls.TLSExtension) string {
	if len(extensions) == 0 {
		return "00000"
	}

	extTypes := make([]uint16, 0, len(extensions))
	for _, ext := range extensions {
		// Используем type assertion для известных расширений
		// В utls нет метода Type(), поэтому определяем по структуре
		switch ext.(type) {
		case *utls.SNIExtension:
			extTypes = append(extTypes, 0x0000)
		case *utls.ALPNExtension:
			extTypes = append(extTypes, 0x0010)
		case *utls.StatusRequestExtension:
			extTypes = append(extTypes, 0x0005)
		case *utls.SupportedCurvesExtension:
			extTypes = append(extTypes, 0x000A)
		case *utls.SupportedPointsExtension:
			extTypes = append(extTypes, 0x000B)
		case *utls.SignatureAlgorithmsExtension:
			extTypes = append(extTypes, 0x000D)
		case *utls.SessionTicketExtension:
			extTypes = append(extTypes, 0x0023)
		case *utls.GenericExtension:
			// Для GenericExtension тип не определить без доп. парсинга
			// Пропускаем или добавляем заглушку
		}
	}

	if len(extTypes) == 0 {
		return "00000"
	}

	// Сортируем
	sort.Slice(extTypes, func(i, j int) bool { return extTypes[i] < extTypes[j] })

	// Формируем строку для хеша
	parts := make([]string, len(extTypes))
	for i, t := range extTypes {
		parts[i] = strconv.FormatUint(uint64(t), 16)
	}

	hash := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(hash[:])[:5]
}

func getSignatureAlgosString(extensions []utls.TLSExtension) string {
	// Ищем расширение signature_algorithms
	for _, ext := range extensions {
		if sigExt, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			// Получаем алгоритмы подписей
			algos := make([]uint16, len(sigExt.SupportedSignatureAlgorithms))
			for i, a := range sigExt.SupportedSignatureAlgorithms {
				algos[i] = uint16(a)
			}

			if len(algos) == 0 {
				return "00000"
			}

			// Сортируем
			sort.Slice(algos, func(i, j int) bool { return algos[i] < algos[j] })

			// Формируем строку для хеша
			parts := make([]string, len(algos))
			for i, a := range algos {
				parts[i] = strconv.FormatUint(uint64(a), 16)
			}

			hash := sha256.Sum256([]byte(strings.Join(parts, ",")))
			return hex.EncodeToString(hash[:])[:5]
		}
	}
	return "00000"
}
