package grpc

import (
	"context"
	"time"
)

type ClientData struct {
	ClientID          string
	SessionKey        string
	MasterKey         string
	ServerCertificate string // публичный сертификат (PEM)
	ServerPrivateKey  string // приватный ключ (PEM) - ДОБАВЛЯЕМ
	CreatedAt         time.Time
}

type ClientStorage interface {
	// Сохранить данные клиента при регистрации
	SaveClient(ctx context.Context, data *ClientData) error

	// Получить клиента по session_key
	GetClientBySession(ctx context.Context, sessionKey string) (*ClientData, error)

	// Получить клиента по client_id
	GetClientByID(ctx context.Context, clientID string) (*ClientData, error)

	// Проверить существует ли уже клиент
	ClientExists(ctx context.Context) (bool, error)

	// Удалить клиента (опционально)
	DeleteClient(ctx context.Context, sessionKey string) error
}
