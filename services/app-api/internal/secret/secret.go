// Package secret makes and hashes the app API's bearer secrets: pairing
// codes (short, typed or scanned by people) and refresh tokens (long, kept by
// apps). Only their SHA-256 hashes are stored.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Crockford's base32: no I, L, O or U, so codes are easy to read aloud.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeLength is the number of symbols in a pairing code: 60 bits.
const CodeLength = 12

const refreshPrefix = "jrt_"

// ErrMalformed means the input cannot be a code or token we issued.
var ErrMalformed = errors.New("malformed")

// NewPairingCode returns a random code formatted as XXXX-XXXX-XXXX.
func NewPairingCode() (string, error) {
	raw := make([]byte, CodeLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var b strings.Builder
	for i, v := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[v&31]) // 256 is a multiple of 32: unbiased
	}
	return b.String(), nil
}

// NormalizeCode undoes what people do to codes: case, spaces, dashes, and
// the letters Crockford's base32 reads as digits (O→0, I/L→1).
func NormalizeCode(code string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case ' ', '-', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(alphabet, r) {
			return "", ErrMalformed
		}
		b.WriteRune(r)
	}
	if b.Len() != CodeLength {
		return "", ErrMalformed
	}
	return b.String(), nil
}

// NewRefreshToken returns a random 256-bit token.
func NewRefreshToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return refreshPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// CheckRefreshToken rejects strings that cannot be a token we issued, so
// garbage never reaches the database.
func CheckRefreshToken(token string) error {
	raw, ok := strings.CutPrefix(token, refreshPrefix)
	if !ok {
		return ErrMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return ErrMalformed
	}
	return nil
}

// Hash is what the database keeps.
func Hash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
