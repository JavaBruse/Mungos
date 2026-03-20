package server

import (
	"context"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetHashSNIandJa4HashTable(ctx context.Context, req *pb.AuthRequest) (*pb.HashTable, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("GetHashSNIandJa4HashTable called")

	sniHash, err := s.storage.GetSNITableHash(ctx)
	if err != nil {
		logger.Error("Failed to get SNI table hash: %v", err)
		return nil, status.Error(codes.Internal, "failed to get SNI hash")
	}

	ja4Hash, err := s.storage.GetJA4TableHash(ctx)
	if err != nil {
		logger.Error("Failed to get JA4 table hash: %v", err)
		return nil, status.Error(codes.Internal, "failed to get JA4 hash")
	}

	return &pb.HashTable{
		SniHash: sniHash,
		Ja4Hash: ja4Hash,
	}, nil
}
