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

// DownloadSNIDatabase - отправка сжатой SNI БД клиенту
func (s *Server) DownloadSNIDatabase(req *pb.SNIDataChunkRequest, stream pb.SnifferService_DownloadSNIDatabaseServer) error {
	if !s.checkAuth(stream.Context(), req.GetSessionKey()) {
		return status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("DownloadSNIDatabase started, session: %s", req.SessionKey)

	entries, err := s.storage.GetAllSNIEntries(stream.Context())
	if err != nil {
		return status.Error(codes.Internal, "failed to get SNI database")
	}

	// Конвертируем в protobuf список
	protoList := &pb.SNIEntryList{
		Entries: make([]*pb.SNIEntry, len(entries)),
	}
	for i, e := range entries {
		protoList.Entries[i] = models.SNIEntryToProto(&e)
	}

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

		chunk := &pb.SNIDataChunk{
			SessionKey: req.SessionKey,
			Data:       compressedData[offset:end],
			IsLast:     end == totalSize,
			TotalSize:  int32(totalSize),
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	logger.Info("DownloadSNIDatabase completed, total size: %d bytes", totalSize)
	return nil
}

// UploadSNIDatabase - прием сжатой SNI БД от клиента
func (s *Server) UploadSNIDatabase(stream pb.SnifferService_UploadSNIDatabaseServer) error {
	firstChunk, err := stream.Recv()
	if err != nil {
		return err
	}

	if !s.checkAuth(stream.Context(), firstChunk.GetSessionKey()) {
		return status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("UploadSNIDatabase started")

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

	protoList := &pb.SNIEntryList{}
	if err := utils.DecompressProto(compressed.Bytes(), protoList); err != nil {
		return status.Error(codes.Internal, "failed to decompress data")
	}

	entries := make([]models.SNIEntry, len(protoList.Entries))
	for i, p := range protoList.Entries {
		entries[i] = *models.SNIEntryFromProto(p)
	}

	if err := s.storage.ReplaceSNIDatabase(stream.Context(), entries); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return stream.SendAndClose(&pb.SNIDataChunkResponse{
		Success:     true,
		Message:     "SNI database uploaded successfully",
		TotalChunks: int32(chunks),
	})
}

// UpdateOrSaveSNIEntry - обновление или сохранение одной SNI записи
func (s *Server) UpdateOrSaveSNIEntry(ctx context.Context, req *pb.SNIEntry) (*pb.SNIEntry, error) {
	if !s.checkAuth(ctx, req.GetSessionKey()) {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}

	logger.Info("UpdateOrSaveSNIEntry: id=%s, service=%s, sni=%s", req.Id, req.Service, req.Sni)

	entry := models.SNIEntryFromProto(req)
	if err := s.storage.UpdateSNIStat(ctx, entry.Service, entry.SNI); err != nil {
		logger.Error("Failed to save SNI entry: %v", err)
		return nil, status.Error(codes.Internal, "failed to save entry")
	}

	return req, nil
}
