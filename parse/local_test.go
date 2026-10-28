package parse

import "testing"

// TestNormalizeChecksum pins every lock-file checksum form the parsers hand to
// normalizeChecksum: the npm/yarn/uv prefixes, the two bare-hex lengths, and the
// empty result for anything else. These are characterisation tests; the literal
// expected outputs are the oracle from local.go's PackageChecksum doc comment.
func TestNormalizeChecksum(t *testing.T) {
	const (
		sha256      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		sha1        = "0123456789abcdef0123456789abcdef01234567"
		mixedSha256 = "aBcDeF0123456789aBcDeF0123456789aBcDeF0123456789aBcDeF0123456789"
	)
	cases := []struct {
		name string
		in   string
		want PackageChecksum
	}{
		{"sha512 prefix", "sha512-dGVzdC1jaGVja3N1bQ==", PackageChecksum{"SHA-512", "dGVzdC1jaGVja3N1bQ=="}},
		{"sha256 colon prefix", "sha256:" + sha256, PackageChecksum{"SHA-256", sha256}},
		{"sha256 dash prefix", "sha256-" + sha256, PackageChecksum{"SHA-256", sha256}},
		{"sha1 colon prefix", "sha1:" + sha1, PackageChecksum{"SHA-1", sha1}},
		{"h1 prefix", "h1:FVa0UyV8QX2L", PackageChecksum{"H1", "FVa0UyV8QX2L"}},
		{"bare 64 hex", sha256, PackageChecksum{"SHA-256", sha256}},
		{"bare 40 hex", sha1, PackageChecksum{"SHA-1", sha1}},
		{"mixed-case 64 hex", mixedSha256, PackageChecksum{"SHA-256", mixedSha256}},
		{"40 chars non-hex", "gggggggggggggggggggggggggggggggggggggggg", PackageChecksum{}},
		{"whitespace wrapped", " \t sha256-" + sha256 + "\n", PackageChecksum{"SHA-256", sha256}},
	}
	for _, tc := range cases {
		if got := normalizeChecksum(tc.in); got != tc.want {
			t.Errorf("normalizeChecksum(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// TestIsHex is a truth table over the ASCII range: exactly 0-9, a-f and A-F are
// accepted, every other rune is rejected, plus a couple of multi-rune strings.
func TestIsHex(t *testing.T) {
	for r := rune(0); r < 128; r++ {
		want := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if got := isHex(string(r)); got != want {
			t.Errorf("isHex(%q) = %v, want %v", string(r), got, want)
		}
	}
	if !isHex("deadBEEF") {
		t.Error(`isHex("deadBEEF") = false, want true`)
	}
	if isHex("dead beef") {
		t.Error(`isHex("dead beef") = true, want false`)
	}
}
