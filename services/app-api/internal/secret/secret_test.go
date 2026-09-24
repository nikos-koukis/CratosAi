package secret

import (
	"strings"
	"testing"
)

func TestPairingCodesAreRandomReadableAndForgiving(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		code, err := NewPairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 14 || code[4] != '-' || code[9] != '-' {
			t.Fatalf("format %q", code)
		}
		if seen[code] {
			t.Fatalf("repeated code %q", code)
		}
		seen[code] = true
		normalized, err := NormalizeCode(" " + strings.ToLower(code) + " ")
		if err != nil || normalized != strings.ReplaceAll(code, "-", "") {
			t.Fatalf("normalize %q = %q, %v", code, normalized, err)
		}
	}
	// Letters people confuse with digits count as those digits.
	a, _ := NormalizeCode("O1L0-ABCD-EFGH")
	b, _ := NormalizeCode("0110-ABCD-EFGH")
	if a != b || a == "" {
		t.Fatalf("%q != %q", a, b)
	}
	for _, bad := range []string{"", "ABCD-EFGH", "ABCD-EFGH-JKMNP", "ABCD-EFGH-JKU!", "ABCD-EFGH-JKMU"} {
		if _, err := NormalizeCode(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRefreshTokens(t *testing.T) {
	token, err := NewRefreshToken()
	if err != nil || CheckRefreshToken(token) != nil || !strings.HasPrefix(token, "jrt_") {
		t.Fatalf("token %q: %v", token, err)
	}
	other, _ := NewRefreshToken()
	if token == other || string(Hash(token)) == string(Hash(other)) || len(Hash(token)) != 32 {
		t.Fatal("tokens or hashes collide")
	}
	for _, bad := range []string{"", "jrt_", "jrt_short", "abc_" + token[4:], token + "x"} {
		if CheckRefreshToken(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
