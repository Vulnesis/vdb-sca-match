package version

import "testing"

// TestRecencyNoPanic feeds every recency engine hostile strings. The engines
// index into regexp groups and token lists, so an empty or truncated input is
// the likeliest way for one of them to panic.
func TestRecencyNoPanic(t *testing.T) {
	ids := []string{
		"apple", "backport-branches", "browser-extension", "calver", "chocolatey",
		"db-majorminor", "docker", "git-ref", "github-release", "go-toolchain", "java",
		"jetbrains", "letter-suffix", "linux-kernel", "nodejs", "npm-dist-tag", "openssl",
		"php", "python-runtime", "rust-toolchain", "scoop", "ubuntu", "unity", "vscode",
		"windows-version", "winget", "android", "linux",
	}
	inputs := []string{
		"", " ", ".", "-", "+", "v", "1.", ".1", "1..2", "1.2.3.4.5.6", "0", "00.00",
		"99999999999999999999.1.1", "1!", "!1", "1-", "1+", "1.0-", "nightly-", "go", "go1",
		"php-", "refs/", "refs/tags/", "1_", "OpenSSL_", "sha256:", "next-", "rc-", "1(", "(a)",
		"\x00", "é.1", "1.2.3-\xff",
	}
	for _, id := range ids {
		for _, a := range inputs {
			ClassifyScheme(id, a)
			for _, b := range inputs {
				CompareScheme(id, a, b)
			}
		}
	}
}

// TestRecencyOrderingRefusals pins the strings that must stay unordered: a
// floating alias, a branch and a digest never compare, so no caller can sort
// them against real releases.
func TestRecencyOrderingRefusals(t *testing.T) {
	cases := []struct{ scheme, a, b string }{
		{"docker", "latest", "1.2.3"},
		{"github-release", "main", "v1.2.3"},
		{"git-ref", "refs/heads/main", "v1.2.3"},
		{"git-ref", "3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a39", "v1.2.3"},
		{"scoop", "nightly", "1.2.3"},
		{"rust-toolchain", "nightly", "nightly-2026-10-22"},
		{"npm-dist-tag", "latest", "1.2.3"},
		{"nodejs", "lts", "v22.23.4"},
	}
	for _, c := range cases {
		if _, ok := CompareScheme(c.scheme, c.a, c.b); ok {
			t.Errorf("%s: %q vs %q compared; want ok=false", c.scheme, c.a, c.b)
		}
	}
}
