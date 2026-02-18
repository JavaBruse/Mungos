package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"sniffer/core/capture"
	pb "sniffer/core/grpc/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Config struct {
	MasterKey  string
	SnifferID  string
	GRPCPort   int
	CertFile   string
	KeyFile    string
	DBHost     string
	DBPort     int
	DBUser     string
	DBPass     string
	DBName     string
	DBProtocol string
}

type Server struct {
	pb.UnimplementedSnifferServiceServer
	config     *Config
	clientKey  string
	clientID   string
	stats      *StatsCollector
	mu         sync.RWMutex
	serverCert tls.Certificate
	certPEM    []byte
}

type StatsCollector struct {
	packetsTotal atomic.Int64
	bytesTotal   atomic.Int64
	protocols    sync.Map
	apps         sync.Map
}

func NewServer(cfg *Config) *Server {
	serverCert, certPEM := generateServerCert()

	return &Server{
		config:     cfg,
		stats:      &StatsCollector{},
		serverCert: serverCert,
		certPEM:    certPEM,
	}
}

func generateServerCert() (tls.Certificate, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sniffer"},
			CommonName:   "sniffer-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("0.0.0.0")},
		DNSNames:              []string{"localhost", "sniffer", "mungos-sniffer"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	return cert, certPEM
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.GRPCPort))
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
	)

	pb.RegisterSnifferServiceServer(grpcServer, s)
	log.Printf("gRPC TLS server listening on :%d with dynamic cert", s.config.GRPCPort)
	return grpcServer.Serve(lis)
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Проверяем существующую сессию
	if req.GetSessionKey() != "" {
		s.mu.RLock()
		valid := s.clientKey == req.GetSessionKey()
		s.mu.RUnlock()

		if valid {
			log.Printf("Session renewed for client %s", s.clientID)
			return &pb.RegisterResponse{
				Success:           true,
				SessionKey:        req.GetSessionKey(),
				Message:           "session renewed",
				ServerCertificate: string(s.certPEM),
			}, nil
		}

		// Неверный session key
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	// Новый клиент - проверяем master key
	if req.GetMasterKey() != s.config.MasterKey {
		return nil, status.Error(codes.PermissionDenied, "invalid master key")
	}

	// Проверяем, есть ли уже зарегистрированный клиент
	s.mu.RLock()
	hasClient := s.clientKey != ""
	s.mu.RUnlock()

	if hasClient {
		// Уже есть клиент - отказываем
		log.Printf("Rejected new client %s - sniffer already has client %s",
			req.GetSnifferId(), s.clientID)
		return nil, status.Error(codes.AlreadyExists, "sniffer already has a client")
	}

	// Генерируем новый session key
	sessionKey := generateSecureKey()

	// Сохраняем клиента
	s.mu.Lock()
	s.clientKey = sessionKey
	s.clientID = req.GetSnifferId()
	s.mu.Unlock()

	log.Printf("Client registered: ID=%s, session=%s",
		req.GetSnifferId(), sessionKey[:8]+"...")

	return &pb.RegisterResponse{
		Success:           true,
		SessionKey:        sessionKey,
		Message:           "registered successfully",
		ServerCertificate: string(s.certPEM),
	}, nil
}

func (s *Server) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	s.mu.RLock()
	valid := s.clientKey == req.GetSessionKey()
	s.mu.RUnlock()

	if !valid {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	log.Printf("Ping from %s: %s", s.clientID, req.GetMessage())
	return &pb.PingResponse{
		Message:   "pong from Go",
		Timestamp: time.Now().Unix(),
	}, nil
}

func (s *Server) GetStats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
	s.mu.RLock()
	valid := s.clientKey == req.GetSessionKey()
	s.mu.RUnlock()

	if !valid {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	return &pb.StatsResponse{
		PacketsCount: s.stats.packetsTotal.Load(),
		BytesTotal:   s.stats.bytesTotal.Load(),
		Error:        "",
	}, nil
}

func generateSecureKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("key-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func (s *Server) UpdateStats(p *capture.Packet) {
	s.stats.packetsTotal.Add(1)
	s.stats.bytesTotal.Add(int64(p.Length))
}
