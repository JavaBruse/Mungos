package ja4go

import "unicode/utf8"

// TlsVersion соответствует rust-энуму TlsVersion.
type TlsVersion int

const (
	TlsUnknown TlsVersion = iota
	Tls13
	Tls12
	Tls11
	Tls10
	Ssl30
	Ssl20
)

// TlsVersionFromWire конвертирует строку вида "0x0304" в TlsVersion.
func TlsVersionFromWire(s string) TlsVersion {
	switch s {
	case "0x0304":
		return Tls13
	case "0x0303":
		return Tls12
	case "0x0302":
		return Tls11
	case "0x0301":
		return Tls10
	case "0x0300":
		return Ssl30
	case "0x0002":
		return Ssl20
	default:
		return TlsUnknown
	}
}

// String возвращает короткий код версии, как в Rust Display:
// "13", "12", "11", "10", "s3", "s2", или "00" для Unknown.
func (v TlsVersion) String() string {
	switch v {
	case Tls13:
		return "13"
	case Tls12:
		return "12"
	case Tls11:
		return "11"
	case Tls10:
		return "10"
	case Ssl30:
		return "s3"
	case Ssl20:
		return "s2"
	default:
		return "00"
	}
}

// firstLast эквивалентна rust-функции first_last:
// возвращает первую и последнюю ASCII-букву строки,
// заменяя не-ASCII на '9'. Для пустой строки оба значения nil.
func firstLast(s string) (rune, *rune) {
	if s == "" {
		return 0, nil
	}

	// Первый символ
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError || r > 127 {
		r = '9'
	}

	// Второй и далее
	rest := s[size:]
	if rest == "" {
		return r, nil
	}

	var last rune
	for len(rest) > 0 {
		l, sz := utf8.DecodeRuneInString(rest)
		if l == utf8.RuneError || l > 127 {
			l = '9'
		}
		last = l
		rest = rest[sz:]
	}
	return r, &last
}

