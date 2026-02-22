package storage

import (
	"log"
	"os"

	"sniffer/core/capture"
)

// PacketLogger сохраняет пакеты в файл
type PacketLogger struct {
	logger *log.Logger
	file   *os.File
}

// NewPacketLogger создаёт логгер в файл
func NewPacketLogger(filename string) (*PacketLogger, error) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &PacketLogger{
		logger: log.New(file, "", log.LstdFlags),
		file:   file,
	}, nil
}

// Write сохраняет пакет
func (l *PacketLogger) Write(p *capture.Packet) {
	l.logger.Printf("%s %s:%d -> %s:%d [%s] len=%d ttl=%d flags=%s",
		p.Timestamp.Format("2006-01-02 15:04:05.999"),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Protocol,
		p.Length,
		p.TTL,
		p.TCPFlags,
	)
}

// Close закрывает файл
func (l *PacketLogger) Close() error {
	return l.file.Close()
}
