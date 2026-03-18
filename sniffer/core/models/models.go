package models

import "time"

type Packet struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  []string
	Length    int
	TCPFlags  string
	TTL       uint8
	Payload   []byte
	SrcMAC    string
	DstMAC    string
	SrcVendor string
	DstVendor string

	JA4Raw    string // основной JA4 отпечаток (клиент)
	JA4SRaw   string // JA4S отпечаток (сервер)
	JA4HRaw   string // JA4H отпечаток (HTTP)
	JA4XRaw   string // JA4X отпечаток (сертификаты)
	JA4SSHRaw string // JA4SSH отпечаток
	JA4LRaw   string // JA4L отпечаток (latency)
	JA4RRaw   string // raw отпечаток (для отладки)

	// JA4 fields
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
	JA4XFingerprint      *string `json:"ja4x_fingerprint"`
	JA4TFingerprint      *string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     *string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  *string `json:"ja4tscan_fingerprint"`
}
