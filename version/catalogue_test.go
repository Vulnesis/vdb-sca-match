package version

import (
	"sort"
	"strings"
	"testing"
)

// folded lists catalogue entries that have no engine of their own because a
// sibling scheme orders them the same way, with the scheme that stands in.
var folded = map[string]string{
	"ivy":      "gradle", // Ivy's latest-revision comparator is the one Gradle copied
	"coursier": "maven",  // sbt/Coursier differs from ComparableVersion only on rare qualifiers
}

func TestCatalogueAndEnginesAgree(t *testing.T) {
	inCatalogue := map[string]bool{}
	for _, s := range Catalogue() {
		inCatalogue[s.ID] = true
		if s.Name == "" || len(s.Spec) == 0 || s.StableRule == "" {
			t.Errorf("%s: catalogue entry needs a name, a spec URL and a stable rule", s.ID)
		}
		if _, ok := registry[s.ID]; !ok {
			if _, isFolded := folded[s.ID]; !isFolded {
				t.Errorf("catalogue scheme %q has no engine and is not folded into another", s.ID)
			}
		}
	}
	for id := range registry {
		if strings.Contains(id, ":") || id == genericScheme {
			continue
		}
		if !inCatalogue[id] {
			t.Errorf("engine %q is not in schemes.json", id)
		}
	}
	for id, into := range folded {
		if !inCatalogue[id] {
			t.Errorf("folded scheme %q is not in the catalogue", id)
		}
		if _, ok := registry[into]; !ok {
			t.Errorf("folded scheme %q points at %q, which has no engine", id, into)
		}
	}
}

func TestEcosystemTable(t *testing.T) {
	var problems []string
	for eco, id := range ecosystemScheme {
		if _, ok := registry[id]; !ok {
			problems = append(problems, eco+" -> "+id+" (no engine)")
			continue
		}
		s, ok := SchemeByID(id)
		if !ok {
			problems = append(problems, eco+" -> "+id+" (not in catalogue)")
			continue
		}
		known := false
		for _, name := range append(append([]string{}, s.Ecosystems...), s.PurlTypes...) {
			if strings.ToLower(strings.TrimSuffix(name, "?")) == eco {
				known = true
			}
		}
		if !known {
			problems = append(problems, eco+" -> "+id+" (the catalogue entry does not list this ecosystem)")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestSchemeForNormalisesOSVNames(t *testing.T) {
	cases := map[string]string{
		"Debian:12":          "debian",
		"Ubuntu:22.04:LTS":   "debian",
		"Alpine:v3.19":       "alpine",
		"Red Hat":            "rpm",
		"Rocky Linux":        "rpm",
		"PyPI":               "pep440",
		"crates.io":          "cargo",
		"Go":                 "go",
		"RubyGems":           "rubygems",
		"Packagist":          "composer",
		"an-unknown-ecosyst": "generic",
	}
	for eco, want := range cases {
		if got := SchemeFor(eco); got != want {
			t.Errorf("SchemeFor(%q) = %q, want %q", eco, got, want)
		}
	}
}
