package models

import "time"

type Packet struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Length    int
	TCPFlags  string
	TTL       uint8
	Payload   []byte

	// JA4 fields
	JA4Raw         string
	JA4Application string
	JA4Device      string
	JA4OS          string
	JA4Verified    bool
	JA4Confidence  int

	// SNI vector
	SNI        string
	SNIService string
}

type ClientData struct {
	SessionKey        string
	ServerCertificate string
	ServerPrivateKey  string
	CreatedAt         time.Time
}

type SettingsData struct {
	BPFFilter string
	CreatedAt time.Time
}

type JA4DBEntry struct {
	Application          string  `json:"application"`
	Library              *string `json:"library"`
	Device               *string `json:"device"`
	OS                   string  `json:"os"`
	UserAgentString      *string `json:"user_agent_string"`
	CertificateAuthority *string `json:"certificate_authority"`
	ObservationCount     int     `json:"observation_count"`
	Verified             bool    `json:"verified"`
	Notes                *string `json:"notes"`
	JA4Fingerprint       string  `json:"ja4_fingerprint"`
	JA4SFingerprint      *string `json:"ja4s_fingerprint"`
	JA4HFingerprint      *string `json:"ja4h_fingerprint"`
}
