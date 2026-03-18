package ja4go

import (
	"crypto/sha256"
	"encoding/hex"
)

// Hash12 возвращает первые 12 шестнадцатеричных символов SHA‑256 хэша строки.
// Для пустой строки возвращает "000000000000".
func Hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}


