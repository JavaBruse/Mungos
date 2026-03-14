package server

import (
	"context"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"
	"sniffer/core/models"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	logger.Info("%v session key", req.SessionKey)
	logger.Info("%v master key", req.MasterKey)
	if req.GetSessionKey() != "" {
		s.mu.RLock()
		valid := s.clientKey == req.GetSessionKey()
		s.mu.RUnlock()

		if valid {
			logger.Info("Session renewed for client %s", s.clientID)
			return &pb.RegisterResponse{
				Success:           true,
				SessionKey:        req.GetSessionKey(),
				Message:           "session renewed",
				ServerCertificate: string(s.certPEM),
			}, nil
		}

		if s.storage != nil && s.storage.Enabled() {
			client, err := s.storage.GetClientBySession(ctx, req.GetSessionKey())
			if err == nil && client != nil {
				s.mu.Lock()
				s.clientKey = client.SessionKey
				s.mu.Unlock()

				logger.Info("Session restored from DB")
				return &pb.RegisterResponse{
					Success:           true,
					SessionKey:        client.SessionKey,
					Message:           "session restored",
					ServerCertificate: string(s.certPEM),
				}, nil
			}
		}

		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	if req.GetMasterKey() != s.config.MasterKey {
		return nil, status.Error(codes.PermissionDenied, "invalid master key")
	}

	if s.storage != nil && s.storage.Enabled() {
		exist, err := s.storage.ClientExists(ctx)
		if err != nil {
			logger.Error("Failed to check client existence: %v", err)
			return nil, status.Error(codes.Internal, "failed to check client")
		}
		if exist {
			logger.Warn("Client already exists in DB, rejecting new registration")
			return nil, status.Error(codes.AlreadyExists, "client already registered")
		}
	}

	sessionKey := generateSecureKey()

	s.mu.Lock()
	s.clientKey = sessionKey
	s.mu.Unlock()

	if s.storage != nil && s.storage.Enabled() {
		clientData := &models.ClientData{
			SessionKey:        sessionKey,
			ServerCertificate: string(s.certPEM),
			ServerPrivateKey:  string(s.keyPEM),
			CreatedAt:         time.Now(),
		}

		if err := s.storage.SaveClient(ctx, clientData); err != nil {
			logger.Error("Failed to save client to DB: %v", err)
		} else {
			logger.Info("Client saved to DB")
		}
	}

	logger.Info("Client registered")

	return &pb.RegisterResponse{
		Success:           true,
		SessionKey:        sessionKey,
		Message:           "registered successfully",
		ServerCertificate: string(s.certPEM),
	}, nil
}
