package server

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
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"sniffer/core/capture"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"
	"sniffer/core/storage/clickhouse"

	_ "github.com/ClickHouse/clickhouse-go/v2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	Storage    *clickhouse.ClickHouseStorage
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
	keyPEM     []byte
	storage    *clickhouse.ClickHouseStorage
}

type StatsCollector struct {
	packetsTotal atomic.Int64
	bytesTotal   atomic.Int64
	protocols    sync.Map
	apps         sync.Map
}

var startTime = time.Now()

func NewServer(cfg *Config) *Server {
	if cfg.Storage != nil && cfg.Storage.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client, err := cfg.Storage.GetClient(ctx, cfg.SnifferID)
		if err == nil && client != nil && client.ServerPrivateKey != "" {
			cert, err := tls.X509KeyPair(
				[]byte(client.ServerCertificate),
				[]byte(client.ServerPrivateKey),
			)
			if err == nil {
				logger.Info("Restored server certificate from DB")
				return &Server{
					config:     cfg,
					stats:      &StatsCollector{},
					serverCert: cert,
					certPEM:    []byte(client.ServerCertificate),
					keyPEM:     []byte(client.ServerPrivateKey),
					storage:    cfg.Storage,
					clientKey:  client.SessionKey,
				}
			}
		}
	}

	serverCert, certPEM, keyPEM := generateServerCert()

	return &Server{
		config:     cfg,
		stats:      &StatsCollector{},
		serverCert: serverCert,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		storage:    cfg.Storage,
		clientKey:  "",
		clientID:   "",
	}
}

func generateServerCert() (tls.Certificate, []byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Error("Failed to generate private key: %v", err)
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
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "sniffer-server", "sniffer"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		logger.Error("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logger.Error("Failed to load key pair: %v", err)
	}

	return cert, certPEM, keyPEM
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
	logger.Info("gRPC TLS server listening on :%d", s.config.GRPCPort)
	return grpcServer.Serve(lis)
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

func (s *Server) checkAuth(ctx context.Context, sessionKey string) bool {
	s.mu.RLock()
	valid := s.clientKey != "" && s.clientKey == sessionKey
	s.mu.RUnlock()

	if valid {
		return true
	}

	if s.storage != nil && s.storage.Enabled() {
		client, err := s.storage.GetClientBySession(ctx, sessionKey)
		if err == nil && client != nil {
			s.mu.Lock()
			s.clientKey = client.SessionKey
			s.mu.Unlock()
			logger.Info("Session restored from DB")
			return true
		}
	}

	return false
}
