package method

import (
	"context"
	"encoding/binary"
	"fmt"
	"sniffer/core/models"
	"sniffer/core/storage/clickhouse"
	"strings"
	"sync"
	"time"

	"sniffer/core/method/ja4go"

	"github.com/google/gopacket/layers"
)

func ProcessJA4(packet *models.Packet, tcp *layers.TCP, db *clickhouse.ClickHouseStorage) *models.Packet {
	if packet == nil || tcp == nil {
		return packet
	}

	// 1) JA4T: только первый SYN (без ACK) в направлении клиента.
	if tcp.SYN && !tcp.ACK {
		opts, mss, wscale := tcpSynOptions(tcp.Options)
		packet.JA4RRaw = ja4go.BuildJA4T(ja4go.BuildJA4TInput{
			WindowSize:  tcp.Window,
			Options:     opts,
			MSS:         mss,
			WindowScale: wscale,
		})
	}

	// 2) TLS/HTTP: делаем минимальный TCP reassembly по Seq и пытаемся разобрать handshake/HTTP.
	if len(tcp.Payload) > 0 {
		dir := tlsDirection(packet, tcp)
		if dir != "" {
			buf := tcpReasmAdd(packet, tcp, dir)

			if dir == "c2s" && packet.JA4Raw == "" {
				if ch, ok := parseTLSClientHello(buf); ok {
					out := ja4go.BuildJA4(ch, ja4go.FormatFlags{WithRaw: true})
					packet.JA4Raw = out.JA4
					packet.JA4RRaw = out.JA4Raw
				}
			}
			if dir == "s2c" && packet.JA4SRaw == "" {
				if sh, ok := parseTLSServerHello(buf); ok {
					out := ja4go.BuildJA4S(sh, ja4go.FormatFlags{WithRaw: true})
					packet.JA4SRaw = out.JA4S
				}
			}

			// HTTP можно пробовать и без reassembly, но буфер даёт шанс поймать заголовок целиком.
			if packet.JA4HRaw == "" {
				if httpIn, ok := parseHTTPRequest(buf); ok {
					out := ja4go.BuildJA4H(httpIn, ja4go.FormatFlags{WithRaw: true})
					packet.JA4HRaw = out.JA4
				}
			}
		}
	}

	if db != nil && db.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if packet.JA4Raw != "" {
			if entry, err := db.LookupJA4(ctx, packet.JA4Raw); err == nil && entry != nil {
				fillPacketFromEntry(packet, entry)
				return packet
			}
		}
		if packet.JA4SRaw != "" {
			if entry, err := db.LookupJA4(ctx, packet.JA4SRaw); err == nil && entry != nil {
				fillPacketFromEntry(packet, entry)
				return packet
			}
		}
		if packet.JA4HRaw != "" {
			if entry, err := db.LookupJA4(ctx, packet.JA4HRaw); err == nil && entry != nil {
				fillPacketFromEntry(packet, entry)
				return packet
			}
		}
	}
	return packet
}

func fillPacketFromEntry(packet *models.Packet, entry *models.Ja4Entry) {
	packet.JA4EntryID = entry.ID
	packet.JA4Application = entry.Application
	packet.JA4OS = entry.OS
	packet.JA4Verified = entry.Verified
	packet.JA4Confidence = entry.ObservationCount
	if entry.Device != "" {
		packet.JA4Device = entry.Device
	}
}

// -----------------------------------------------------------------------------
// Минимальный TCP reassembly под ранние handshake/HTTP.

type reasmKey struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	dir     string // "c2s" / "s2c"
}

type reasmState struct {
	mu       sync.Mutex
	segments map[uint32][]byte
	nextSeq  *uint32
	contig   []byte
	lastSeen time.Time
}

var reasm sync.Map // map[reasmKey]*reasmState

func tlsDirection(p *models.Packet, tcp *layers.TCP) string {
	// Упрощение: считаем TLS-клиента той стороной, которая шлёт на 443.
	// Если у тебя не 443 — можно расширить позже (по первому SYN).
	if p.DstPort == 443 {
		return "c2s"
	}
	if p.SrcPort == 443 {
		return "s2c"
	}
	return ""
}

func tcpReasmAdd(p *models.Packet, tcp *layers.TCP, dir string) []byte {
	k := reasmKey{
		srcIP:   p.SrcIP,
		dstIP:   p.DstIP,
		srcPort: p.SrcPort,
		dstPort: p.DstPort,
		dir:     dir,
	}

	now := p.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	v, _ := reasm.LoadOrStore(k, &reasmState{
		segments: map[uint32][]byte{},
		lastSeen: now,
	})
	st := v.(*reasmState)

	st.mu.Lock()
	defer st.mu.Unlock()

	// Простая очистка по TTL состояния, чтобы не течь памятью.
	if now.Sub(st.lastSeen) > 30*time.Second {
		st.segments = map[uint32][]byte{}
		st.nextSeq = nil
		st.contig = nil
	}
	st.lastSeen = now

	seq := tcp.Seq
	if len(tcp.Payload) == 0 {
		return st.contig
	}
	// Сохраняем сегмент. Если дубликат — оставляем первый.
	if _, ok := st.segments[seq]; !ok {
		cp := make([]byte, len(tcp.Payload))
		copy(cp, tcp.Payload)
		st.segments[seq] = cp
	}

	// Инициализация nextSeq как минимального seq из сегментов.
	if st.nextSeq == nil {
		min := seq
		for s := range st.segments {
			if s < min {
				min = s
			}
		}
		st.nextSeq = &min
	}

	// Подклеиваем непрерывные сегменты.
	for st.nextSeq != nil {
		data, ok := st.segments[*st.nextSeq]
		if !ok {
			break
		}
		st.contig = append(st.contig, data...)
		delete(st.segments, *st.nextSeq)
		next := *st.nextSeq + uint32(len(data))
		*st.nextSeq = next
	}

	// Ограничение буфера: нам достаточно первых нескольких KB для ClientHello/ServerHello и HTTP.
	const maxBuf = 64 * 1024
	if len(st.contig) > maxBuf {
		st.contig = st.contig[len(st.contig)-maxBuf:]
	}

	return st.contig
}

func tcpSynOptions(opts []layers.TCPOption) (kinds []uint8, mss *uint16, wscale *uint8) {
	for _, o := range opts {
		kinds = append(kinds, uint8(o.OptionType))
		switch o.OptionType {
		case layers.TCPOptionKindMSS:
			if len(o.OptionData) >= 2 {
				v := binary.BigEndian.Uint16(o.OptionData[:2])
				mss = &v
			}
		case layers.TCPOptionKindWindowScale:
			if len(o.OptionData) >= 1 {
				v := uint8(o.OptionData[0])
				wscale = &v
			}
		}
	}
	return kinds, mss, wscale
}

// ---- Минимальный TLS ClientHello/ServerHello парсер ----
// Важно: это парсит только те случаи, когда ClientHello/ServerHello лежит целиком в одном tcp.Payload.
// Для полноценной поддержки нужно TCP reassembly.

func parseTLSClientHello(payload []byte) (ja4go.BuildJA4Input, bool) {
	var out ja4go.BuildJA4Input
	hs, ok := tlsHandshakeFromRecord(payload)
	if !ok || len(hs) < 4 || hs[0] != 0x01 {
		return out, false
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+bodyLen > len(hs) {
		return out, false
	}
	b := hs[4 : 4+bodyLen]

	// legacy_version
	if len(b) < 2 {
		return out, false
	}
	out.Version = fmt.Sprintf("0x%02x%02x", b[0], b[1])
	i := 2
	// random(32)
	if i+32 > len(b) {
		return out, false
	}
	i += 32
	// session id
	if i >= len(b) {
		return out, false
	}
	sidLen := int(b[i])
	i++
	if i+sidLen > len(b) {
		return out, false
	}
	i += sidLen
	// cipher suites
	if i+2 > len(b) {
		return out, false
	}
	csLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if i+csLen > len(b) || csLen%2 != 0 {
		return out, false
	}
	for j := 0; j < csLen; j += 2 {
		cs := binary.BigEndian.Uint16(b[i+j : i+j+2])
		out.Ciphers = append(out.Ciphers, fmt.Sprintf("0x%04x", cs))
	}
	i += csLen
	// compression methods
	if i >= len(b) {
		return out, false
	}
	compLen := int(b[i])
	i++
	if i+compLen > len(b) {
		return out, false
	}
	i += compLen
	// extensions
	if i == len(b) {
		return out, true
	}
	if i+2 > len(b) {
		return out, false
	}
	extLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if i+extLen > len(b) {
		return out, false
	}
	exts := b[i : i+extLen]
	parseTLSExtensionsClient(exts, &out)
	return out, true
}

func parseTLSServerHello(payload []byte) (ja4go.BuildJA4SInput, bool) {
	var out ja4go.BuildJA4SInput
	hs, ok := tlsHandshakeFromRecord(payload)
	if !ok || len(hs) < 4 || hs[0] != 0x02 {
		return out, false
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+bodyLen > len(hs) {
		return out, false
	}
	b := hs[4 : 4+bodyLen]
	if len(b) < 2+32 {
		return out, false
	}
	// legacy_version
	out.Version = fmt.Sprintf("0x%02x%02x", b[0], b[1])
	i := 2 + 32
	// session id echo
	if i >= len(b) {
		return out, false
	}
	sidLen := int(b[i])
	i++
	if i+sidLen > len(b) {
		return out, false
	}
	i += sidLen
	// cipher suite
	if i+2 > len(b) {
		return out, false
	}
	cs := binary.BigEndian.Uint16(b[i : i+2])
	out.Cipher = fmt.Sprintf("0x%04x", cs)
	i += 2
	// compression method
	if i >= len(b) {
		return out, false
	}
	i++
	// extensions
	if i == len(b) {
		return out, true
	}
	if i+2 > len(b) {
		return out, false
	}
	extLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if i+extLen > len(b) {
		return out, false
	}
	exts := b[i : i+extLen]
	parseTLSExtensionsServer(exts, &out)
	return out, true
}

func tlsHandshakeFromRecord(payload []byte) ([]byte, bool) {
	// TLSPlaintext: type(1) version(2) length(2)
	if len(payload) < 5 {
		return nil, false
	}
	if payload[0] != 0x16 { // handshake record
		return nil, false
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if 5+recLen > len(payload) {
		return nil, false
	}
	return payload[5 : 5+recLen], true
}

func parseTLSExtensionsClient(exts []byte, out *ja4go.BuildJA4Input) {
	i := 0
	for i+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[i : i+2])
		l := int(binary.BigEndian.Uint16(exts[i+2 : i+4]))
		i += 4
		if i+l > len(exts) {
			return
		}
		body := exts[i : i+l]
		i += l

		out.Exts = append(out.Exts, typ)
		if typ == 0 { // server_name
			out.HasSNI = true
		}
		if typ == 16 { // ALPN
			// alpn extension: list_len(2) [ name_len(1) name ... ]...
			if len(body) >= 3 {
				listLen := int(binary.BigEndian.Uint16(body[0:2]))
				if 2+listLen <= len(body) && listLen > 0 {
					p := body[2 : 2+listLen]
					if len(p) >= 1 {
						n := int(p[0])
						if 1+n <= len(p) {
							out.ALPN = string(p[1 : 1+n])
						}
					}
				}
			}
		}
		if typ == 43 { // supported_versions (client)
			// len(1) + versions (2 bytes each)
			if len(body) >= 1 {
				n := int(body[0])
				if 1+n <= len(body) && n%2 == 0 {
					for j := 0; j < n; j += 2 {
						v := binary.BigEndian.Uint16(body[1+j : 1+j+2])
						out.SupportedVersions = append(out.SupportedVersions, fmt.Sprintf("0x%04x", v))
					}
				}
			}
		}
		if typ == 13 { // signature_algorithms
			// len(2) + algs (2 bytes each)
			if len(body) >= 2 {
				n := int(binary.BigEndian.Uint16(body[0:2]))
				if 2+n <= len(body) && n%2 == 0 {
					for j := 0; j < n; j += 2 {
						a := binary.BigEndian.Uint16(body[2+j : 2+j+2])
						out.SigHashAlgs = append(out.SigHashAlgs, fmt.Sprintf("0x%04x", a))
					}
				}
			}
		}
	}
}

func parseTLSExtensionsServer(exts []byte, out *ja4go.BuildJA4SInput) {
	i := 0
	for i+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[i : i+2])
		l := int(binary.BigEndian.Uint16(exts[i+2 : i+4]))
		i += 4
		if i+l > len(exts) {
			return
		}
		body := exts[i : i+l]
		i += l

		out.Exts = append(out.Exts, typ)
		if typ == 16 { // ALPN (server) same structure, first protocol only
			if len(body) >= 3 {
				listLen := int(binary.BigEndian.Uint16(body[0:2]))
				if 2+listLen <= len(body) && listLen > 0 {
					p := body[2 : 2+listLen]
					if len(p) >= 1 {
						n := int(p[0])
						if 1+n <= len(p) {
							out.ALPN = string(p[1 : 1+n])
						}
					}
				}
			}
		}
		if typ == 43 { // supported_versions (server): selected_version(2)
			if len(body) == 2 {
				v := binary.BigEndian.Uint16(body[0:2])
				out.SupportedVersions = append(out.SupportedVersions, fmt.Sprintf("0x%04x", v))
			}
		}
	}
}

// ---- HTTP request parsing (минимально) ----
func parseHTTPRequest(payload []byte) (ja4go.BuildJA4HInput, bool) {
	var out ja4go.BuildJA4HInput
	// Быстрый фильтр: должен быть printable и содержать "HTTP/"
	s := string(payload)
	if !strings.Contains(s, "HTTP/") {
		return out, false
	}
	// Берём только заголовки до \r\n\r\n
	end := strings.Index(s, "\r\n\r\n")
	if end < 0 {
		return out, false
	}
	head := s[:end]
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return out, false
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) < 3 {
		return out, false
	}
	out.Method = parts[0]
	out.Version = parts[len(parts)-1]
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		out.Headers = append(out.Headers, ln)
		lc := strings.ToLower(ln)
		if strings.HasPrefix(lc, "cookie:") {
			out.Cookies = strings.TrimSpace(ln[len("cookie:"):])
		}
		if strings.HasPrefix(lc, "accept-language:") {
			out.Language = strings.TrimSpace(ln[len("accept-language:"):])
		}
	}
	return out, true
}
