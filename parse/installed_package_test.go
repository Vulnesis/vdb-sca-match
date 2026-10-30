package parse

import (
	"fmt"
	"testing"
)

// TestSplitInstalledPackageNoPanic exercises every supported ecosystem with
// arbitrary, malformed and boundary inputs. The function is a heuristic
// splitter, so the hard invariants are: it never panics, it returns the same
// result for the same input, and a token with no package in it (blank,
// quotes only, a URL) yields an empty name and version.
func TestSplitInstalledPackageNoPanic(t *testing.T) {
	tokens := []string{
		"",
		"   ",
		"'",
		`""`,
		",",
		"=",
		"==",
		"@",
		"@@",
		"http://example.com/pkg",
		"https://example.com/pkg@1.2.3",
		"pkg",
		"pkg=",
		"pkg==",
		"=1.2.3",
		"==1.2.3",
		"@scope/pkg@1.2.3",
		"@scope/pkg",
		"pkg@1.2.3@4.5.6",
		"pkg==1.2.3==3.4.5",
		"pkg:1.2.3:4.5.6",
		" group:artifact:1.0 ",
		`"pkg==1.2.3",`,
	}

	ecosystems := []string{
		"apk", "deb", "rpm", "arch", "conda",
		"npm",
		"pypi", "gem", "golang", "composer", "cargo", "nuget",
		"maven",
		"unknown",
	}

	// Blank, quote-only and URL tokens carry no package, whatever the ecosystem.
	empty := map[string]bool{
		"": true, "   ": true, "'": true, `""`: true,
		"http://example.com/pkg": true, "https://example.com/pkg@1.2.3": true,
	}
	for _, eco := range ecosystems {
		for _, tok := range tokens {
			name, version := splitInstalledPackage(tok, eco)
			name2, version2 := splitInstalledPackage(tok, eco)
			if name != name2 || version != version2 {
				t.Errorf("splitInstalledPackage(%q, %q) non-deterministic: got (%q, %q) then (%q, %q)",
					tok, eco, name, version, name2, version2)
			}
			if empty[tok] && (name != "" || version != "") {
				t.Errorf("splitInstalledPackage(%q, %q) = (%q, %q), want empty", tok, eco, name, version)
			}
		}
	}
}

// TestSplitInstalledPackageExamples documents the expected splits for the forms
// callers rely on across npm, pypi, maven and distro packages.
func TestSplitInstalledPackageExamples(t *testing.T) {
	cases := []struct {
		tok, ecosystem string
		wantName       string
		wantVersion    string
	}{
		// npm scoped and unscoped
		{"@scope/pkg@1.2.3", "npm", "@scope/pkg", "1.2.3"},
		{"@scope/pkg", "npm", "@scope/pkg", ""},
		{"pkg@1.2.3", "npm", "pkg", "1.2.3"},
		{"pkg", "npm", "pkg", ""},

		// pypi
		{"pkg==1.2.3", "pypi", "pkg", "1.2.3"},
		{"pkg@1.2.3", "pypi", "pkg", "1.2.3"},
		{"pkg:v1.2.3", "pypi", "pkg", "1.2.3"},
		{"pkg:1.2.3", "pypi", "pkg", "1.2.3"},

		// maven
		{"group:artifact:1.0", "maven", "group:artifact", "1.0"},

		// apk/deb
		{"pkg=1.2.3", "apk", "pkg", "1.2.3"},
		{"pkg==1.2.3", "apk", "pkg", "1.2.3"},
		{"pkg=1.2.3", "deb", "pkg", "1.2.3"},
		{"pkg==1.2.3", "deb", "pkg", "1.2.3"},
		{"pkg=1.2.3", "rpm", "pkg", "1.2.3"},
		{"pkg==1.2.3", "rpm", "pkg", "1.2.3"},

		// other ecosystems that share the pypi-like separators
		{"pkg@1.2.3", "gem", "pkg", "1.2.3"},
		{"pkg@1.2.3", "golang", "pkg", "1.2.3"},
		{"pkg@1.2.3", "composer", "pkg", "1.2.3"},
		{"pkg@1.2.3", "cargo", "pkg", "1.2.3"},
		{"pkg@1.2.3", "nuget", "pkg", "1.2.3"},
	}

	for _, c := range cases {
		name := fmt.Sprintf("%s/%q", c.ecosystem, c.tok)
		t.Run(name, func(t *testing.T) {
			gotName, gotVersion := splitInstalledPackage(c.tok, c.ecosystem)
			if gotName != c.wantName || gotVersion != c.wantVersion {
				t.Errorf("splitInstalledPackage(%q, %q) = (%q, %q), want (%q, %q)",
					c.tok, c.ecosystem, gotName, gotVersion, c.wantName, c.wantVersion)
			}
		})
	}
}
