package ja4go

import (
	"sort"
	"strings"
)

// BuildJA4HInput HTTP-поля
type BuildJA4HInput struct {
	// GET POST
	Method string
	// HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/3
	Version string
	//Accept-Language
	Language string
	// Cookie/Referer
	// HTTP/2  http2.header.name.
	Headers []string
	// Cookies Cookie HTTP/1.1 cookie value (HTTP/2).
	Cookies string
}

type BuildJA4HOutput struct {
	JA4        string
	JA4Raw     string
	JA4RawOrig string
}

func BuildJA4H(in BuildJA4HInput, flags FormatFlags) BuildJA4HOutput {
	methodCode := httpMethodCode(in.Method)
	versionCode := httpVersionCode(in.Version)

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

	var headersNormalized []string
	for _, h := range headerNames {
		headersNormalized = append(headersNormalized, h)
	}
	headersHash := Hash12(strings.Join(headersNormalized, ","))

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
		ja4hR = firstChunk.String() + "_" +
			strings.Join(headerNames, ",") + "_"
		ja4hRO = ja4hR
		if len(cookieFields) > 0 {
			ja4hR += strings.Join(sortedFields, ",") + "_" + strings.Join(sortedValues, ",")
			ja4hRO += strings.Join(cookieFields, ",") + "_" + strings.Join(cookieValues, ",")
		}
	}

	return BuildJA4HOutput{
		JA4:        ja4h,
		JA4Raw:     ja4hR,
		JA4RawOrig: ja4hRO,
	}
}

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

func httpPrimaryLanguage(lang string) string {
	lang = strings.TrimSpace(lang)
	if lang == "" {
		return ""
	}
	primary := strings.SplitN(lang, ",", 2)[0]
	primary = strings.ReplaceAll(primary, "-", "")
	return strings.ToLower(primary)
}

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
