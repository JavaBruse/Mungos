package server

import (
	"context"
	"time"

	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session key")
	}

	logger.Info("Ping from %s: %s", s.clientID, req.GetMessage())

	return &pb.PingResponse{
		Message:   "pong from Go",
		Timestamp: time.Now().Unix(),
	}, nil
}
