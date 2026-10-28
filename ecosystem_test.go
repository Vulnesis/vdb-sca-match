package match

import (
	"strings"
	"testing"
)

func TestCanonicalEcosystem(t *testing.T) {
	cases := map[string]string{
		"golang":   "go",
		"gem":      "rubygems",
		"composer": "packagist",
		"pypi":     "pypi",
		"python":   "pypi",
		"pip":      "pypi",
		"PyPI":     "pypi",
		"npm":      "npm",
		"cargo":    "cargo",
		"NPM":      "npm",
		"":         "",
	}
	for in, want := range cases {
		if got := CanonicalEcosystem(in); got != want {
			t.Errorf("CanonicalEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEcosystemEvidence(t *testing.T) {
	// PURL types resolve to canonical + populated evidence.
	canonical, urls, vendors, ok := EcosystemEvidence("golang")
	if !ok || canonical != "go" {
		t.Fatalf("golang: canonical=%q ok=%v", canonical, ok)
	}
	if !contains(urls, "https://pkg.go.dev") || !contains(vendors, "go") {
		t.Errorf("golang evidence missing: urls=%v vendors=%v", urls, vendors)
	}

	if _, urls, _, ok := EcosystemEvidence("npm"); !ok || !contains(urls, "https://www.npmjs.com") {
		t.Errorf("npm must include www.npmjs.com: urls=%v ok=%v", urls, ok)
	}

	// Empty and unmapped ecosystems report ok=false so callers fall back.
	if _, _, _, ok := EcosystemEvidence(""); ok {
		t.Errorf("empty ecosystem must be unmapped")
	}
	if c, _, _, ok := EcosystemEvidence("deb"); ok || c != "deb" {
		t.Errorf("deb must be unmapped, got canonical=%q ok=%v", c, ok)
	}
}

func TestVersionRangeEcoClauses(t *testing.T) {
	// Empty ecosystem → name-only (TRUE), no extra args (unchanged contract).
	if o, in, args := versionRangeEcoClauses(""); o != "TRUE" || in != "TRUE" || args != nil {
		t.Errorf("empty eco: outer=%q inner=%q args=%v", o, in, args)
	}

	// Known ecosystem (golang→go) → authoritative predicate with a case-insensitive,
	// trailing-path-tolerant registry-URL LIKE; inner clause uses the `ai.` subquery
	// alias (never a bare `a.`); args carry url patterns + vendor lists.
	outer, inner, args := versionRangeEcoClauses("golang")
	if !strings.Contains(outer, `LOWER(a."collectionURL") LIKE ANY($2::text[])`) ||
		!strings.Contains(outer, `LOWER(split_part(a."vendor", ':', 1)) = ANY($3::text[])`) {
		t.Errorf("known eco outer predicate wrong: %q", outer)
	}
	if strings.Contains(inner, "a.\"") {
		t.Errorf("inner clause must use the ai. alias for the subquery: %q", inner)
	}
	if len(args) != 2 {
		t.Fatalf("known eco must carry url+vendor args, got %v", args)
	}
	urls, ok := args[0].([]string)
	if !ok || !contains(urls, "https://pkg.go.dev%") {
		t.Errorf("url arg must be a lowercased prefix pattern: %v", args[0])
	}
	if vendors, ok := args[1].([]string); !ok || !contains(vendors, "go") {
		t.Errorf("vendor arg missing go: %v", args[1])
	}

	// Unmapped non-empty ecosystem → legacy substring gate, single eco arg.
	o, _, a := versionRangeEcoClauses("deb")
	if !strings.Contains(o, "LIKE") || len(a) != 1 || a[0] != "deb" {
		t.Errorf("unmapped eco: outer=%q args=%v", o, a)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestNativeOnlyExcludesEveryRegistryAndDistro(t *testing.T) {
	outer, inner, args := nativeOnlyClauses()
	if !strings.Contains(outer, `a."collectionURL"`) || !strings.Contains(inner, `ai."collectionURL"`) || len(args) != 1 {
		t.Fatalf("clauses = %q %q %v", outer, inner, args)
	}
	vendors := args[0].([]string)
	for _, want := range []string{"npm", "pypi", "debian", "red hat", "alpine", "wolfi"} {
		found := false
		for _, v := range vendors {
			found = found || v == want
		}
		if !found {
			t.Errorf("vendor %q is not excluded", want)
		}
	}
}
