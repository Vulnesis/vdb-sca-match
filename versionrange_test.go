package match

import "testing"

func sp(s string) *string { return &s }

// ar builds an affected/unaffected row for evaluateProduct tests.
func ar(status, versionType, version, lessThan, lessThanOrEqual string) affRow {
	return affRow{
		status:          status,
		versionType:     versionType,
		version:         version,
		lessThan:        lessThan,
		lessThanOrEqual: lessThanOrEqual,
	}
}

func TestEvaluateProduct(t *testing.T) {
	cases := []struct {
		name        string
		installed   string
		eco         string
		rows        []affRow
		wantVerdict prodVerdict
		wantMethod  string
	}{
		// ── exact / range / unaffected (parity with the old per-row tests) ──
		{"below lessThan", "1.5.0", "npm", []affRow{ar("affected", "semver", "", "2.0.0", "")}, prodSpecific, "version-range:lessThan"},
		{"at lessThan exclusive", "2.0.0", "npm", []affRow{ar("affected", "semver", "", "2.0.0", "")}, prodNone, ""},
		{"above lessThan", "3.0.0", "npm", []affRow{ar("affected", "semver", "", "2.0.0", "")}, prodNone, ""},
		{"at lessThanOrEqual inclusive", "2.0.0", "npm", []affRow{ar("affected", "semver", "", "", "2.0.0")}, prodSpecific, "version-range:lessThanOrEqual"},
		{"exact version", "1.0.0", "npm", []affRow{ar("affected", "semver", "1.0.0", "", "")}, prodSpecific, "version-range:exact"},
		{"unaffected range covers installed", "1.0.0", "npm", []affRow{ar("unaffected", "semver", "1.0.0", "9.9.9", "")}, prodUnaffected, ""},
		{"empty installed matches nothing", "", "npm", []affRow{ar("affected", "semver", "1.0.0", "", "")}, prodNone, ""},
		{"unparseable falls back to string exact", "not-semver", "npm", []affRow{ar("affected", "semver", "not-semver", "", "")}, prodSpecific, "version-range:exact"},
		{"generic numeric ordering", "1.2.9", "deb", []affRow{ar("affected", "generic", "", "1.2.10", "")}, prodSpecific, "version-range:lessThan"},

		// ── Rule 2: wildcard is a valid all-versions match ──
		{"wildcard affected matches all", "5.0.0", "npm", []affRow{ar("affected", "semver", "*", "", "")}, prodWildcard, "version-range:wildcard"},

		// ── lower-bound (introduced) gating ──
		{"below introduced lower bound", "1.0.0", "npm", []affRow{ar("affected", "semver", "2.0.0", "3.0.0", "")}, prodNone, ""},
		{"within introduced..lessThan", "2.5.0", "npm", []affRow{ar("affected", "semver", "2.0.0", "3.0.0", "")}, prodSpecific, "version-range:lessThan"},
		{"zero lower bound is unbounded", "0.5.0", "npm", []affRow{ar("affected", "semver", "0", "1.0.0", "")}, prodSpecific, "version-range:lessThan"},

		// ── segment wildcards ──
		{"segment wildcard 8.x matches 8.3.1", "8.3.1", "npm", []affRow{ar("affected", "semver", "8.x", "", "")}, prodSpecific, "version-range:segwild"},
		{"segment wildcard 8.x rejects 9.0.0", "9.0.0", "npm", []affRow{ar("affected", "semver", "8.x", "", "")}, prodNone, ""},

		// ── CVE 5.1 precedence: exact-unaffected beats range-affected ──
		{"exact unaffected overrides affected range", "2.5.0", "npm",
			[]affRow{ar("affected", "semver", "", "3.0.0", ""), ar("unaffected", "semver", "2.5.0", "", "")}, prodUnaffected, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotV, gotM, _ := evaluateProduct(c.installed, c.eco, c.rows)
			if gotV != c.wantVerdict || gotM != c.wantMethod {
				t.Fatalf("evaluateProduct(%q) = (%v,%q), want (%v,%q)", c.installed, gotV, gotM, c.wantVerdict, c.wantMethod)
			}
		})
	}
}

// CVE 5.1 changes[]: a version past an in-range fix step is no longer affected.
func TestEffectiveRowStatusChanges(t *testing.T) {
	row := affRow{
		status: "affected", versionType: "semver", version: "1.0.0", lessThan: "3.0.0",
		changes: []verChange{{at: "2.0.0", status: "unaffected"}},
	}
	if got := effectiveRowStatus("2.5.0", "npm", row); got != "unaffected" {
		t.Fatalf("post-fix 2.5.0 effective status = %q, want unaffected", got)
	}
	if got := effectiveRowStatus("1.5.0", "npm", row); got != "affected" {
		t.Fatalf("pre-fix 1.5.0 effective status = %q, want affected", got)
	}
}

// evaluateCVE folds products: any affected wins; drop only when every product
// with data agrees unaffected; inconclusive stays as a coarse "unknown".
func TestEvaluateCVE(t *testing.T) {
	cd := func(products ...[]affRow) *cveData {
		c := &cveData{products: map[string][]affRow{}}
		for i, p := range products {
			id := string(rune('a' + i))
			c.productOrder = append(c.productOrder, id)
			c.products[id] = p
		}
		return c
	}

	t.Run("any affected product wins", func(t *testing.T) {
		v, _, _ := evaluateCVE("2.5.0", "npm", cd(
			[]affRow{ar("unaffected", "semver", "2.5.0", "", "")},
			[]affRow{ar("affected", "semver", "", "3.0.0", "")},
		))
		if v != cveSpecific {
			t.Fatalf("verdict = %v, want cveSpecific", v)
		}
	})

	t.Run("all-unaffected drops", func(t *testing.T) {
		v, _, _ := evaluateCVE("2.5.0", "npm", cd(
			[]affRow{ar("unaffected", "semver", "2.5.0", "", "")},
		))
		if v != cveDrop {
			t.Fatalf("verdict = %v, want cveDrop", v)
		}
	})

	t.Run("inconclusive stays as unknown", func(t *testing.T) {
		v, _, _ := evaluateCVE("5.0.0", "npm", cd(
			[]affRow{ar("affected", "semver", "", "2.0.0", "")}, // installed above range
		))
		if v != cveUnknown {
			t.Fatalf("verdict = %v, want cveUnknown", v)
		}
	})
}

func TestBuildRangeString(t *testing.T) {
	cases := []struct {
		versionValue, lessThan, lessThanOrEqual *string
		want                                    string
	}{
		{sp("1.0.0"), sp("2.0.0"), nil, ">=1.0.0, <2.0.0"},
		{nil, nil, sp("3.0.0"), "<=3.0.0"},
		{sp("1.0.0"), nil, nil, ">=1.0.0"},
		{nil, nil, nil, ""},
		{sp("*"), sp("2.0.0"), nil, "<2.0.0"}, // wildcard lower dropped
		{sp("0"), sp("2.0.0"), nil, "<2.0.0"}, // zero lower dropped
	}
	for _, c := range cases {
		if got := buildRangeString(c.versionValue, c.lessThan, c.lessThanOrEqual); got != c.want {
			t.Errorf("buildRangeString = %q, want %q", got, c.want)
		}
	}
}
