FROM golang:1.24-bullseye AS builder
RUN apt-get update && apt-get install -y libpcap-dev protobuf-compiler
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN protoc --go_out=. --go-grpc_out=. proto/sniffer.proto
RUN go build -o main .

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libpcap0.8 ca-certificates
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 3331
CMD ["./main"]
