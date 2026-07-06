package match

import (
	"strings"
	"testing"
)

func TestNormalizePypiName(t *testing.T) {
	// PEP 503: lowercase and collapse any run of . _ - to a single -.
	cases := map[string]string{
		"Django":                 "django",
		"zope.interface":         "zope-interface",
		"zope_interface":         "zope-interface",
		"zope-interface":         "zope-interface",
		"google__cloud..storage": "google-cloud-storage",
		"  Flask  ":              "flask",
	}
	for in, want := range cases {
		if got := normalizePypiName(in); got != want {
			t.Errorf("normalizePypiName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameMatchExpr(t *testing.T) {
	// pypi applies PEP 503 normalisation on the DB side and compares to the
	// pre-normalised $1; other ecosystems keep a plain case-fold equality.
	pypi := nameMatchExpr("a", true)
	if !strings.Contains(pypi, "REGEXP_REPLACE") || !strings.Contains(pypi, "'[-_.]+'") || !strings.Contains(pypi, "= $1") {
		t.Errorf("pypi name expr should PEP503-normalise: %q", pypi)
	}
	plain := nameMatchExpr("ai", false)
	if !strings.Contains(plain, `LOWER(COALESCE(ai."packageName", ai.product)) = LOWER($1)`) {
		t.Errorf("non-pypi name expr should be a plain case-fold: %q", plain)
	}
}
