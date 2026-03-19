package utils

import (
	"bytes"
	"compress/gzip"
	"io"

	"google.golang.org/protobuf/proto"
)

// CompressProto упаковывает protobuf сообщение в gzip
func CompressProto(msg proto.Message) ([]byte, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressProto распаковывает gzip в protobuf сообщение
func DecompressProto(data []byte, msg proto.Message) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()

	uncompressed, err := io.ReadAll(gz)
	if err != nil {
		return err
	}

	return proto.Unmarshal(uncompressed, msg)
}
