package version

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// The golden vectors under testdata/ were produced by the real reference
// implementation of each scheme wherever one could be run (see each vector's
// `source`). This file holds the engine to them; testdata/known_divergences.json
// lists, with a reason, every vector the engine deliberately answers differently.

type stabilityVector struct {
	Scheme    string   `json:"scheme"`
	Ecosystem string   `json:"ecosystem"`
	Version   string   `json:"version"`
	Stable    bool     `json:"stable"`
	Reasons   []string `json:"reasons"`
	Orderable bool     `json:"orderable"`
	Source    string   `json:"source"`
	Variant   string   `json:"variant"`
}

type orderingVector struct {
	Scheme    string   `json:"scheme"`
	Ascending []string `json:"ascending"`
	Source    string   `json:"source"`
	Variant   string   `json:"variant"`
}

type divergence struct {
	Scheme  string `json:"scheme"`
	Kind    string `json:"kind"` // "stability" or "ordering"
	Key     string `json:"key"`  // the version, or "a < b" for an ordering pair
	Reason  string `json:"reason"`
	Variant string `json:"variant,omitempty"`
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func loadDivergences(t *testing.T) map[string]string {
	t.Helper()
	var ds []divergence
	if _, err := os.Stat("testdata/known_divergences.json"); err == nil {
		loadJSON(t, "testdata/known_divergences.json", &ds)
	}
	out := map[string]string{}
	for _, d := range ds {
		out[d.Scheme+"|"+d.Kind+"|"+d.Key] = d.Reason
	}
	return out
}

// vectorScheme resolves a vector's scheme id, preferring a registered
// "scheme:variant" engine (vcpkg has four manifest version schemes).
func vectorScheme(scheme, variant string) string {
	if variant != "" {
		if _, ok := registry[scheme+":"+variant]; ok {
			return scheme + ":" + variant
		}
	}
	return scheme
}

func sameReasons(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	// calver-shape is informational and never decides stability.
	clean := func(in []string) []string {
		out := in[:0]
		for _, s := range in {
			if s != ReasonCalverShape && s != "backport" {
				out = append(out, s)
			}
		}
		return out
	}
	x, y = clean(x), clean(y)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

func TestSchemeVectors(t *testing.T) {
	var data struct {
		Stability []stabilityVector `json:"stability"`
		Ordering  []orderingVector  `json:"ordering"`
	}
	loadJSON(t, "testdata/scheme_vectors.json", &data)
	known := loadDivergences(t)

	type tally struct{ pass, fail, divergent int }
	stab := map[string]*tally{}
	ord := map[string]*tally{}
	get := func(m map[string]*tally, k string) *tally {
		if m[k] == nil {
			m[k] = &tally{}
		}
		return m[k]
	}
	report := os.Getenv("VERSION_REPORT") != ""
	var unregistered = map[string]int{}

	for _, v := range data.Stability {
		id := vectorScheme(v.Scheme, v.Variant)
		if _, ok := registry[id]; !ok {
			unregistered[v.Scheme]++
			continue
		}
		got := ClassifyScheme(id, v.Version)
		tl := get(stab, v.Scheme)
		ok := got.Orderable == v.Orderable && got.Stable == v.Stable
		if ok && !v.Stable && v.Orderable {
			ok = sameReasons(got.Reasons, v.Reasons)
		}
		switch {
		case ok:
			tl.pass++
		case known[v.Scheme+"|stability|"+v.Version] != "":
			tl.divergent++
		default:
			tl.fail++
			msg := fmt.Sprintf("%s %q: want orderable=%v stable=%v %v, got orderable=%v stable=%v %v (%s)",
				v.Scheme, v.Version, v.Orderable, v.Stable, v.Reasons, got.Orderable, got.Stable, got.Reasons, v.Source)
			if report {
				fmt.Println("STABILITY-FAIL", msg)
			} else {
				t.Errorf("%s", msg)
			}
		}
	}

	for _, o := range data.Ordering {
		oid := vectorScheme(o.Scheme, o.Variant)
		if _, ok := registry[oid]; !ok {
			continue
		}
		tl := get(ord, o.Scheme)
		bad := false
		for i := 0; i < len(o.Ascending) && !bad; i++ {
			for j := i + 1; j < len(o.Ascending); j++ {
				c, ok := CompareScheme(oid, o.Ascending[i], o.Ascending[j])
				if ok && c == -1 {
					continue
				}
				key := o.Ascending[i] + " < " + o.Ascending[j]
				if known[o.Scheme+"|ordering|"+key] != "" {
					tl.divergent++
					continue
				}
				bad = true
				msg := fmt.Sprintf("%s ordering %q < %q: got cmp=%d ok=%v (%s)", o.Scheme, o.Ascending[i], o.Ascending[j], c, ok, o.Source)
				if report {
					fmt.Println("ORDERING-FAIL", msg)
				} else {
					t.Errorf("%s", msg)
				}
				break
			}
		}
		if bad {
			tl.fail++
		} else {
			tl.pass++
		}
	}

	if report {
		var ids []string
		for id := range stab {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			s, o := stab[id], ord[id]
			if o == nil {
				o = &tally{}
			}
			fmt.Printf("SCHEME %-18s stability pass=%-3d fail=%-3d | ordering pass=%-2d fail=%-2d\n", id, s.pass, s.fail, o.pass, o.fail)
		}
		var un []string
		for id, n := range unregistered {
			un = append(un, fmt.Sprintf("%s(%d)", id, n))
		}
		sort.Strings(un)
		fmt.Println("UNREGISTERED", strings.Join(un, " "))
	}
}

// A divergence is an admission that the engine answers differently from a vector.
// One the engine no longer needs, or one that names no vector, is stale and must go.
func TestKnownDivergencesAreCurrent(t *testing.T) {
	var data struct {
		Stability []stabilityVector `json:"stability"`
	}
	loadJSON(t, "testdata/scheme_vectors.json", &data)
	var ds []divergence
	loadJSON(t, "testdata/known_divergences.json", &ds)
	for _, d := range ds {
		if d.Reason == "" {
			t.Errorf("%s %s %q: a divergence needs a reason", d.Scheme, d.Kind, d.Key)
		}
		if d.Kind != "stability" {
			t.Errorf("%s %q: only stability divergences are checked here; add ordering support before listing one", d.Scheme, d.Key)
			continue
		}
		found := false
		for _, v := range data.Stability {
			if v.Scheme != d.Scheme || v.Version != d.Key {
				continue
			}
			found = true
			got := ClassifyScheme(vectorScheme(v.Scheme, v.Variant), v.Version)
			agrees := got.Orderable == v.Orderable && got.Stable == v.Stable
			if agrees && !v.Stable && v.Orderable {
				agrees = sameReasons(got.Reasons, v.Reasons)
			}
			if agrees {
				t.Errorf("%s %q is listed as a divergence but the engine now agrees with the vector: remove it", d.Scheme, d.Key)
			}
		}
		if !found {
			t.Errorf("%s %q names no vector", d.Scheme, d.Key)
		}
	}
}
