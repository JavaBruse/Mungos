package models

import (
	pb "sniffer/core/grpc/proto"
	"time"
)

type Packet struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcIPType string // "local", "private", "public"
	DstIPType string // "local", "private", "public"
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

	JA4EntryID string
	SNIEntryID string
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

type ConnectionInsight struct {
	// Соединение
	LocalIP    string
	LocalPorts []uint16
	RemoteIP   string
	RemotePort uint16

	// Статистика
	TotalPackets      int64
	TotalBytes        int64
	FirstPacketTime   int64
	LastPacketTime    int64
	SynCount          int64
	FinCount          int64
	RstCount          int64
	IdentifiedPackets int64

	JA4Candidates []JA4Candidate
	SNICandidates []SNICandidate
}

type JA4Candidate struct {
	ID          string
	Fingerprint string
	Application string
	Device      string
	OS          string
	Count       int64
	Confidence  int
	Hop         int
}

type SNICandidate struct {
	ID         string
	SNI        string
	Service    string
	Count      int64
	Confidence int
	Hop        int
}

type SNIEntry struct {
	ID              string
	Service         string
	SNI             string
	OccurrenceCount int
	FirstSeen       time.Time
	LastSeen        time.Time
}

type Ja4Entry struct {
	ID               string
	Fingerprint      string
	Application      string
	Library          string
	Device           string
	OS               string
	ObservationCount int
	Verified         bool
	FingerprintType  string
	UpdatedAt        int64
}

// ToProto конвертирует внутреннюю структуру в protobuf
func (e *Ja4Entry) ToProto() *pb.JA4Entry {
	return &pb.JA4Entry{
		Id:               e.ID,
		Fingerprint:      e.Fingerprint,
		Application:      e.Application,
		Library:          e.Library,
		Device:           e.Device,
		Os:               e.OS,
		ObservationCount: int32(e.ObservationCount),
		Verified:         e.Verified,
		FingerprintType:  e.FingerprintType,
	}
}

// FromProto конвертирует protobuf во внутреннюю структуру
func FromProto(p *pb.JA4Entry) *Ja4Entry {
	return &Ja4Entry{
		ID:               p.Id,
		Fingerprint:      p.Fingerprint,
		Application:      p.Application,
		Library:          p.Library,
		Device:           p.Device,
		OS:               p.Os,
		ObservationCount: int(p.ObservationCount),
		Verified:         p.Verified,
		FingerprintType:  p.FingerprintType,
	}
}

// ToProtoList конвертирует список
func ToProtoList(entries []Ja4Entry) *pb.JA4EntryList {
	list := &pb.JA4EntryList{}
	for _, e := range entries {
		list.Entries = append(list.Entries, e.ToProto())
	}
	return list
}

// FromProtoList конвертирует список из protobuf
func FromProtoList(list *pb.JA4EntryList) []Ja4Entry {
	var entries []Ja4Entry
	for _, p := range list.Entries {
		entries = append(entries, *FromProto(p))
	}
	return entries
}

// SNIEntryToProto конвертирует внутреннюю SNIEntry в protobuf
func SNIEntryToProto(e *SNIEntry) *pb.SNIEntry {
	return &pb.SNIEntry{
		Id:              e.ID,
		Service:         e.Service,
		Sni:             e.SNI,
		OccurrenceCount: int32(e.OccurrenceCount),
		FirstSeen:       e.FirstSeen.UnixNano(),
		LastSeen:        e.LastSeen.UnixNano(),
	}
}

// SNIEntryFromProto конвертирует protobuf во внутреннюю SNIEntry
func SNIEntryFromProto(p *pb.SNIEntry) *SNIEntry {
	return &SNIEntry{
		ID:              p.Id,
		Service:         p.Service,
		SNI:             p.Sni,
		OccurrenceCount: int(p.OccurrenceCount),
		FirstSeen:       time.Unix(0, p.FirstSeen),
		LastSeen:        time.Unix(0, p.LastSeen),
	}
}

// SNIEntryListToProto конвертирует список внутренних структур в protobuf список
func SNIEntryListToProto(entries []SNIEntry) *pb.SNIEntryList {
	list := &pb.SNIEntryList{
		Entries: make([]*pb.SNIEntry, len(entries)),
	}
	for i, e := range entries {
		list.Entries[i] = SNIEntryToProto(&e)
	}
	return list
}

// SNIEntryListFromProto конвертирует protobuf список во внутренние структуры
func SNIEntryListFromProto(list *pb.SNIEntryList) []SNIEntry {
	if list == nil {
		return nil
	}
	entries := make([]SNIEntry, len(list.Entries))
	for i, p := range list.Entries {
		entries[i] = *SNIEntryFromProto(p)
	}
	return entries
}

type RelatedAddress struct {
	RemoteIP   string
	RemotePort uint16
	Count      int64
}
