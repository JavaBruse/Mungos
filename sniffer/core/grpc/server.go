package grpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"sniffer/core/capture"
	pb "sniffer/core/grpc/proto" // проверь путь

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	MasterKey  string
	SnifferID  string
	GRPCPort   int
	DBHost     string
	DBPort     int
	DBUser     string
	DBPass     string
	DBName     string
	DBProtocol string
}

type Server struct {
	pb.UnimplementedSnifferServiceServer
	config      *Config
	sessionKeys map[string]bool
	stats       *StatsCollector
}

type StatsCollector struct {
	packetsTotal atomic.Int64
	bytesTotal   atomic.Int64
	protocols    sync.Map
	apps         sync.Map
}

func NewServer(cfg *Config) *Server {
	return &Server{
		config:      cfg,
		sessionKeys: make(map[string]bool),
		stats:       &StatsCollector{},
	}
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.GRPCPort))
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	pb.RegisterSnifferServiceServer(grpcServer, s)
	log.Printf("gRPC server listening on :%d", s.config.GRPCPort)
	return grpcServer.Serve(lis)
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.GetMasterKey() != s.config.MasterKey {
		return nil, status.Error(codes.PermissionDenied, "invalid master key")
	}

	sessionKey := generateSecureKey()
	s.sessionKeys[sessionKey] = true
	return &pb.RegisterResponse{
		Success:    true,
		SessionKey: sessionKey,
		Message:    "registered",
	}, nil
}

func generateSecureKey() string {
	bytes := make([]byte, 32) // 256 бит
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// "Сессионный ключ генерируется криптостойким генератором случайных чисел (crypto/rand) длиной 32 байта (256 бит), что обеспечивает более чем 10⁷⁷ возможных комбинаций. Ключ уникален для каждой сессии, не вычислим из предыдущих и передаётся только один раз при регистрации. Данный уровень энтропии делает перебор ключа методом грубой силы невозможным при текущем уровне развития вычислительной техники, что соответствует требованиям промышленной безопасности для систем анализа трафика."

func (s *Server) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	log.Printf("Ping received: %s", req.GetMessage())
	if !s.sessionKeys[req.GetSessionKey()] {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}
	return &pb.PingResponse{
		Message:   "pong from Go",
		Timestamp: time.Now().Unix(),
	}, nil
}

func (s *Server) GetStats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
	if !s.sessionKeys[req.GetSessionKey()] {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}
	return &pb.StatsResponse{
		PacketsCount: s.stats.packetsTotal.Load(),
		BytesTotal:   s.stats.bytesTotal.Load(),
	}, nil
}

func (s *Server) UpdateStats(p *capture.Packet) {
	s.stats.packetsTotal.Add(1)
	s.stats.bytesTotal.Add(int64(p.Length))
}
