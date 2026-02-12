FROM golang:1.24-bullseye AS builder
RUN apt-get update && apt-get install -y libpcap-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libpcap0.8
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]