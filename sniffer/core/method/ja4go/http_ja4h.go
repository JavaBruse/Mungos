package ja4go

import (
	"sort"
	"strings"
)

// BuildJA4HInput описывает нормализованные HTTP-поля
// (уже разобранные из HTTP/1.1 или HTTP/2).
type BuildJA4HInput struct {
	// Метод запроса, как в протоколе: "GET", "POST" и т.п.
	Method string
	// Версия: "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3".
	Version string
	// Язык из Accept-Language, как строка заголовка (может быть пустой).
	Language string
	// Полный список заголовков запроса (имена, как в протоколе, без дубликата Cookie/Referer
	// для HTTP/1.1; для HTTP/2 — значения http2.header.name).
	Headers []string
	// Cookies — строка как в заголовке Cookie (HTTP/1.1) или объединённые cookie value (HTTP/2).
	// В простом варианте используем одну строку, как в Python-реализации.
	Cookies string
}

// BuildJA4HOutput содержит итоговые строки JA4H/JA4H_r/JA4H_ro.
type BuildJA4HOutput struct {
	JA4    string
	JA4Raw string
	JA4RawOrig string
}

// BuildJA4H реализует спецификацию JA4H в том же виде, как Python/ja4h.py:
// ge11cr13enus_.... и варианты *_r/_ro.
func BuildJA4H(in BuildJA4HInput, flags FormatFlags) BuildJA4HOutput {
	methodCode := httpMethodCode(in.Method)
	versionCode := httpVersionCode(in.Version)

	// cookie / referer маркеры
	cookieMarker := 'n'
	if in.Cookies != "" {
		cookieMarker = 'c'
	}
	refererMarker := 'n'
	for _, h := range in.Headers {
		if strings.EqualFold(h, "referer") {
			refererMarker = 'r'
			break
		}
	}

	// Нормализованные имена заголовков (без cookie/referer и псевдозаголовков).
	var headerNames []string
	for _, h := range in.Headers {
		name := h
		if i := strings.IndexByte(h, ':'); i >= 0 {
			name = h[:i]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, ":") {
			continue
		}
		if strings.EqualFold(name, "cookie") || strings.EqualFold(name, "referer") {
			continue
		}
		headerNames = append(headerNames, name)
	}

	headerLen := len(headerNames)
	if headerLen > 99 {
		headerLen = 99
	}

	lang := httpPrimaryLanguage(in.Language)
	lang = truncateTo(4, lang)

	firstChunk := strings.Builder{}
	firstChunk.WriteString(methodCode)
	firstChunk.WriteString(versionCode)
	firstChunk.WriteRune(cookieMarker)
	firstChunk.WriteRune(refererMarker)
	firstChunk.WriteString(twoDigits(headerLen))
	firstChunk.WriteString(lang)

	// Хэдеры для хеширования — в нижнем регистре.
	var headersNormalized []string
	for _, h := range headerNames {
		headersNormalized = append(headersNormalized, h)
	}
	headersHash := Hash12(strings.Join(headersNormalized, ","))

	// Cookie-пары.
	var cookieFields, cookieValues []string
	if in.Cookies != "" {
		parts := strings.Split(in.Cookies, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			nameVal := strings.SplitN(p, "=", 2)
			name := strings.TrimSpace(nameVal[0])
			if name == "" {
				continue
			}
			var val string
			if len(nameVal) == 2 {
				val = strings.TrimSpace(nameVal[1])
			}
			cookieFields = append(cookieFields, name)
			if val != "" {
				cookieValues = append(cookieValues, name+"="+val)
			} else {
				cookieValues = append(cookieValues, name)
			}
		}
	}

	// Отсортированные cookie-поля/значения.
	sortedFields := append([]string(nil), cookieFields...)
	sortedValues := append([]string(nil), cookieValues...)
	sort.Strings(sortedFields)
	sort.Strings(sortedValues)

	var cookiesHash, cookieValsHash string
	if len(sortedFields) > 0 {
		cookiesHash = Hash12(strings.Join(sortedFields, ","))
		cookieValsHash = Hash12(strings.Join(sortedValues, ","))
	} else {
		cookiesHash = strings.Repeat("0", 12)
		cookieValsHash = strings.Repeat("0", 12)
	}

	ja4h := firstChunk.String() + "_" + headersHash + "_" + cookiesHash + "_" + cookieValsHash

	var ja4hR, ja4hRO string
	if flags.WithRaw {
		// Raw: оригинальный порядок заголовков.
		ja4hR = firstChunk.String() + "_" +
			strings.Join(headerNames, ",") + "_"
		ja4hRO = ja4hR
		if len(cookieFields) > 0 {
			ja4hR += strings.Join(sortedFields, ",") + "_" + strings.Join(sortedValues, ",")
			ja4hRO += strings.Join(cookieFields, ",") + "_" + strings.Join(cookieValues, ",")
		}
	}

	return BuildJA4HOutput{
		JA4:       ja4h,
		JA4Raw:    ja4hR,
		JA4RawOrig: ja4hRO,
	}
}

// httpMethodCode даёт 2-буквенный код, как в Rust/Python.
func httpMethodCode(m string) string {
	switch strings.ToUpper(m) {
	case "CONNECT":
		return "co"
	case "DELETE":
		return "de"
	case "GET":
		return "ge"
	case "HEAD":
		return "he"
	case "OPTIONS":
		return "op"
	case "PATCH":
		return "pa"
	case "POST":
		return "po"
	case "PUT":
		return "pu"
	case "TRACE":
		return "tr"
	default:
		return "??"
	}
}

// httpVersionCode маппит строку версии к "10"/"11"/"20"/"30".
func httpVersionCode(v string) string {
	switch v {
	case "HTTP/1.0":
		return "10"
	case "HTTP/1.1":
		return "11"
	case "HTTP/2":
		return "20"
	case "HTTP/3":
		return "30"
	default:
		return "00"
	}
}

// httpPrimaryLanguage аналогичен Rust primary_language.
func httpPrimaryLanguage(lang string) string {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return ""
	}
	primary := strings.SplitN(lang, ",", 2)[0]
	primary = strings.ReplaceAll(primary, "-", "")
	return strings.ToLower(primary)
}

// truncateTo эквивалентна Rust truncate_to.
func truncateTo(n int, s string) string {
	runes := []rune(s)
	if len(runes) < n {
		for len(runes) < n {
			runes = append(runes, '0')
		}
		return string(runes)
	}
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

