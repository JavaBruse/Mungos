FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY ../sniffer/go.mod ../sniffer/go.sum ./
RUN go mod download
COPY ../sniffer/ .
RUN go build -o main .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]