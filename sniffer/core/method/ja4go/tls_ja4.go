package ja4go

import (
	"sort"
	"strconv"
	"strings"
)

type FormatFlags struct {
	WithRaw       bool
	OriginalOrder bool
}

type BuildJA4Input struct {
	// true — QUIC (UDP), false — обычный TLS поверх TCP.
	IsQUIC bool

	// Основная версия TLS, строка вида "0x0304" и т.п.
	// Если SupportedVersions не пуст, берётся максимальная из них (без GREASE).
	Version string
	// Список supported_versions из расширения (могут содержать GREASE).
	SupportedVersions []string

	// Список шифров из ClientHello, строки вида "0x1301".
	Ciphers []string
	// Список extension type (u16) в порядке появления.
	Exts []uint16

	// Есть ли SNI (наличие extension server_name).
	HasSNI bool

	// ALPN-строка из ClientHello (первое значение).
	ALPN string

	// Список сигнатурных алгоритмов из signature_algorithms, строки "0x0403" и т.п.
	SigHashAlgs []string
}

// BuildJA4Output соответствует OutClient (без pkt_ja4 и sni).
type BuildJA4Output struct {
	// ja4 или ja4_o
	JA4 string
	// ja4_r или ja4_ro (если WithRaw == true)
	JA4Raw string
}

// BuildJA4 строит JA4/JA4_r (или JA4_o/JA4_ro) из уже разобранных полей.
func BuildJA4(in BuildJA4Input, flags FormatFlags) BuildJA4Output {
	// Копии, чтобы не портить вход.
	ciphers := append([]string(nil), in.Ciphers...)
	exts := append([]uint16(nil), in.Exts...)

	// TLS версия: либо максимальная из supported_versions без GREASE, либо Version.
	versionWire := in.Version
	if len(in.SupportedVersions) > 0 {
		var filtered []string
		for _, v := range in.SupportedVersions {
			if !isGreaseStr(v) {
				filtered = append(filtered, v)
			}
		}
		if len(filtered) > 0 {
			sort.Strings(filtered)
			versionWire = filtered[len(filtered)-1]
		}
	}
	tlsVer := TlsVersionFromWire(versionWire)

	// Маркеры: QUIC, SNI, кол-во шифров/экстов, ALPN.
	quicMarker := 't'
	if in.IsQUIC {
		quicMarker = 'q'
	}
	sniMarker := 'i'
	if in.HasSNI {
		sniMarker = 'd'
	}

	alpn0, alpn1 := firstLast(in.ALPN)
	if alpn0 == 0 {
		alpn0 = '0'
	}
	if alpn1 == nil {
		// односимвольный ALPN — второй символ "0".
		alpn1 = new(rune)
		*alpn1 = '0'
	}

	// Кол-во шифров и экстов (до 99).
	nrCiphers := len(ciphers)
	if nrCiphers > 99 {
		nrCiphers = 99
	}
	nrExts := len(exts)
	if nrExts > 99 {
		nrExts = 99
	}

	// Если original_order == false, удаляем SNI/ALPN экстеншены из списка и сортируем.
	if !flags.OriginalOrder {
		filtered := make([]uint16, 0, len(exts))
		for _, e := range exts {
			if e == tlsExtServerName || e == tlsExtALPN {
				continue
			}
			filtered = append(filtered, e)
		}
		exts = filtered
	}

	firstChunk := strings.Builder{}
	firstChunk.Grow(10)
	firstChunk.WriteRune(quicMarker)
	firstChunk.WriteString(tlsVer.String())
	firstChunk.WriteRune(sniMarker)
	firstChunk.WriteString(twoDigits(nrCiphers))
	firstChunk.WriteString(twoDigits(nrExts))
	firstChunk.WriteRune(alpn0)
	firstChunk.WriteRune(*alpn1)

	// Порядок/сортировка для ciphers/exts.
	if !flags.OriginalOrder {
		// ciphers в виде "1301", "c02b" и т.п.
		normalizeHexNoPrefix(ciphers)
		sort.Strings(ciphers)
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	} else {
		normalizeHexNoPrefix(ciphers)
	}

	ciphersStr := strings.Join(ciphers, ",")
	extsStr := joinExtsHex(exts)

	sigs := normalizeSigAlgs(in.SigHashAlgs)
	sigsStr := strings.Join(sigs, ",")

	extsSigs := extsStr
	if sigsStr != "" {
		extsSigs = extsStr + "_" + sigsStr
	}

	first := firstChunk.String()

	// Hashed fingerprint.
	ja4Hashed := first + "_" + Hash12(ciphersStr) + "_" + Hash12(extsSigs)

	// Raw fingerprint (если нужно).
	ja4Raw := ""
	if flags.WithRaw {
		ja4Raw = first + "_" + ciphersStr + "_" + extsSigs
	}

	return BuildJA4Output{
		JA4:    ja4Hashed,
		JA4Raw: ja4Raw,
	}
}

// BuildJA4SInput — данные для серверного JA4S.
type BuildJA4SInput struct {
	IsQUIC bool

	// Версия TLS (v4.0, см. rust::TlsVersion::new).
	Version string
	// Если SupportedVersions не пуст, берётся максимальная из них (без GREASE).
	SupportedVersions []string

	// Один выбранный шифр, строка "0x1301" и т.п.
	Cipher string

	// Список extension type (u16) в порядке появления (с GREASE).
	Exts []uint16

	// ALPN negotiated string.
	ALPN string
}

type BuildJA4SOutput struct {
	JA4S    string
	JA4SRaw string
}

func BuildJA4S(in BuildJA4SInput, flags FormatFlags) BuildJA4SOutput {
	versionWire := in.Version
	if len(in.SupportedVersions) > 0 {
		var filtered []string
		for _, v := range in.SupportedVersions {
			if !isGreaseStr(v) {
				filtered = append(filtered, v)
			}
		}
		if len(filtered) > 0 {
			sort.Strings(filtered)
			versionWire = filtered[len(filtered)-1]
		}
	}
	tlsVer := TlsVersionFromWire(versionWire)

	quicMarker := 't'
	if in.IsQUIC {
		quicMarker = 'q'
	}

	alpn0, alpn1 := firstLast(in.ALPN)
	if alpn0 == 0 {
		alpn0 = '0'
	}
	if alpn1 == nil {
		alpn1 = new(rune)
		*alpn1 = '0'
	}

	nrExts := len(in.Exts)
	if nrExts > 99 {
		nrExts = 99
	}

	twoChunks := strings.Builder{}
	twoChunks.WriteRune(quicMarker)
	twoChunks.WriteString(tlsVer.String())
	twoChunks.WriteString(twoDigits(nrExts))
	twoChunks.WriteRune(alpn0)
	twoChunks.WriteRune(*alpn1)
	twoChunks.WriteRune('_')

	// cipher: "0x1301" -> "1301"
	cipher := strings.TrimPrefix(strings.ToLower(in.Cipher), "0x")
	twoChunks.WriteString(cipher)

	extsStr := joinExtsHex(in.Exts)
	ja4s := twoChunks.String() + "_" + Hash12(extsStr)

	var ja4sRaw string
	if flags.WithRaw {
		ja4sRaw = twoChunks.String() + "_" + extsStr
	}

	return BuildJA4SOutput{
		JA4S:    ja4s,
		JA4SRaw: ja4sRaw,
	}
}

// --------------------------------------------------------------------

const (
	tlsExtServerName uint16 = 0  // SNI
	tlsExtALPN       uint16 = 16 // ALPN
)

// значения TLS_GREASE_VALUES_STR как в Rust
var greaseStr = map[string]struct{}{
	"0x0a0a": {}, "0x1a1a": {}, "0x2a2a": {}, "0x3a3a": {},
	"0x4a4a": {}, "0x5a5a": {}, "0x6a6a": {}, "0x7a7a": {},
	"0x8a8a": {}, "0x9a9a": {}, "0xaaaa": {}, "0xbaba": {},
	"0xcaca": {}, "0xdada": {}, "0xeaea": {}, "0xfafa": {},
}

func isGreaseStr(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	_, ok := greaseStr[s]
	return ok
}

func twoDigits(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// normalizeHexNoPrefix превращает "0x1301" / "1301" / "1301 " в "1301".
func normalizeHexNoPrefix(vs []string) {
	for i, v := range vs {
		v = strings.ToLower(strings.TrimSpace(v))
		v = strings.TrimPrefix(v, "0x")
		vs[i] = v
	}
}

// joinExtsHex превращает []uint16 в "0005,0017,ff01,0000".
func joinExtsHex(exts []uint16) string {
	if len(exts) == 0 {
		return ""
	}
	var b strings.Builder
	for i, e := range exts {
		if i > 0 {
			b.WriteByte(',')
		}
		s := strconv.FormatUint(uint64(e), 16)
		// zero-pad до 4 символов
		for len(s) < 4 {
			s = "0" + s
		}
		b.WriteString(s)
	}
	return b.String()
}

// normalizeSigAlgs убирает префикс 0x и GREASE из списка сигнатурных алгоритмов.
func normalizeSigAlgs(vs []string) []string {
	var out []string
	for _, v := range vs {
		v = strings.ToLower(strings.TrimSpace(v))
		if isGreaseStr(v) {
			continue
		}
		v = strings.TrimPrefix(v, "0x")
		out = append(out, v)
	}
	return out
}
