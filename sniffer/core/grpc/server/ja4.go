package server

import (
	"bytes"
	"context"
	"io"
	pb "sniffer/core/grpc/proto"
	"sniffer/core/logger"
	"sniffer/core/models"
	"sniffer/core/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DownloadJA4Database - отправка сжатой БД клиенту
func (s *Server) DownloadJA4Database(req *pb.Ja4DataChunkRequest, stream pb.SnifferService_DownloadJA4DatabaseServer) error {
	if !s.checkAuth(stream.Context(), req.GetSessionKey()) {
		return status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("DownloadJA4Database started, session: %s", req.SessionKey)

	entries, err := s.storage.GetAllJA4Entries(stream.Context())
	if err != nil {
		return status.Error(codes.Internal, "failed to get JA4 database")
	}

	// Конвертируем в protobuf список
	protoList := models.ToProtoList(entries)

	compressedData, err := utils.CompressProto(protoList)
	if err != nil {
		return status.Error(codes.Internal, "failed to compress data")
	}

	const chunkSize = 32 * 1024
	totalSize := len(compressedData)

	for offset := 0; offset < totalSize; offset += chunkSize {
		end := offset + chunkSize
		if end > totalSize {
			end = totalSize
		}

		chunk := &pb.Ja4DataChunk{
			SessionKey: req.SessionKey,
			Data:       compressedData[offset:end],
			IsLast:     end == totalSize,
			TotalSize:  int32(totalSize),
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	logger.Info("DownloadJA4Database completed, total size: %d bytes", totalSize)
	return nil
}

// UploadJA4Database - прием сжатой БД от клиента
func (s *Server) UploadJA4Database(stream pb.SnifferService_UploadJA4DatabaseServer) error {
	firstChunk, err := stream.Recv()
	if err != nil {
		return err
	}

	if !s.checkAuth(stream.Context(), firstChunk.GetSessionKey()) {
		return status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("UploadJA4Database started")

	var (
		compressed bytes.Buffer
		sessionKey string
		chunks     int
	)

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		chunks++
		if sessionKey == "" {
			sessionKey = chunk.SessionKey
		}

		compressed.Write(chunk.Data)

		if chunk.IsLast {
			logger.Info("Last chunk received, total size: %d", chunk.TotalSize)
		}
	}

	protoList := &pb.JA4EntryList{}
	if err := utils.DecompressProto(compressed.Bytes(), protoList); err != nil {
		return status.Error(codes.Internal, "failed to decompress data")
	}

	entries := models.FromProtoList(protoList)

	if err := s.storage.ReplaceJA4Database(stream.Context(), entries); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return stream.SendAndClose(&pb.Ja4DataChunkResponse{
		Success:     true,
		Message:     "Database uploaded successfully",
		TotalChunks: int32(chunks),
	})
}

func (s *Server) UpdateOrSaveJa4Entry(ctx context.Context, req *pb.JA4Entry) (*pb.JA4Entry, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	logger.Info("UpdateOrSaveJa4Entry: id=%s", req.Id)
	entry := models.FromProto(req)
	if err := s.storage.SaveDBEntry(ctx, *entry); err != nil {
		logger.Error("Failed to save entry: %v", err)
		return nil, status.Error(codes.Internal, "failed to save entry")
	}

	return req, nil
}
