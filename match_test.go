package match

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── fake Querier / Rows ─────────────────────────────────────────────────────
// A reflection-free stand-in for *pgxpool.Pool. It routes each query to a
// canned row set by table name and decodes into the dest pointer types the
// engine actually uses (*string, **string, **bool). It does NOT validate SQL —
// column-name correctness is verified by review + integration tests.

type fakeRows struct {
	rows [][]any
	idx  int
}

func (r *fakeRows) Next() bool {
	if r.idx < len(r.rows) {
		r.idx++
		return true
	}
	return false
}

func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	for i, d := range dest {
		var v any
		if i < len(row) {
			v = row[i]
		}
		switch p := d.(type) {
		case *string:
			if v == nil {
				*p = ""
			} else {
				*p = v.(string)
			}
		case **string:
			if v == nil {
				*p = nil
			} else {
				s := v.(string)
				*p = &s
			}
		case **bool:
			if v == nil {
				*p = nil
			} else {
				b := v.(bool)
				*p = &b
			}
		default:
			return fmt.Errorf("fakeRows: unsupported dest type %T", d)
		}
	}
	return nil
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

type fakeQuerier struct {
	versionRange [][]any
	purl         [][]any
	cpeAffected  [][]any
	cpeMetadata  [][]any
	crit         [][]any
	alias        [][]any
	queries      []string
}

func (f *fakeQuerier) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	f.queries = append(f.queries, sql)
	switch {
	case strings.Contains(sql, "CVEAffectedVersion"):
		return &fakeRows{rows: f.versionRange}, nil
	case strings.Contains(sql, "PackageVersionCVE"):
		return &fakeRows{rows: f.purl}, nil
	case strings.Contains(sql, "CritRecord"):
		return &fakeRows{rows: f.crit}, nil
	case strings.Contains(sql, "CVEAlias"):
		return &fakeRows{rows: f.alias}, nil
	case strings.Contains(sql, "CVEAffected"):
		return &fakeRows{rows: f.cpeAffected}, nil
	case strings.Contains(sql, "CVEMetadata"):
		return &fakeRows{rows: f.cpeMetadata}, nil
	}
	return &fakeRows{}, nil
}

type errRow struct{}

func (errRow) Scan(_ ...any) error { return fmt.Errorf("not implemented") }

func (f *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row { return errRow{} }

// ── tests ───────────────────────────────────────────────────────────────────

func methodsByCve(ms []Match) map[string]Match {
	out := map[string]Match{}
	for _, m := range ms {
		out[m.CveID] = m
	}
	return out
}

// A CVE reached by version-range + purl + crit must fold all methods into one
// Match, keeping the version-range's VulnerableRange.
func TestMatchDependency_MergesMethods(t *testing.T) {
	q := &fakeQuerier{
		// cveId, affectedId, source, status, versionType, version, lessThan, lessThanOrEqual, isValidVersion, changes
		versionRange: [][]any{
			{"CVE-1", "p1", "nvd", "affected", "semver", nil, "2.0.0", nil, nil, nil},
		},
		purl: [][]any{
			{"CVE-1"}, {"CVE-2"},
		},
		crit: [][]any{
			{"CVE-1"},
		},
	}
	dep := Dependency{Name: "lodash", Version: "1.5.0", Ecosystem: "npm", Purl: "pkg:npm/lodash@1.5.0", Key: "k"}

	matches, err := MatchDependency(context.Background(), q, dep)
	if err != nil {
		t.Fatal(err)
	}
	byCve := methodsByCve(matches)
	if len(byCve) != 2 {
		t.Fatalf("expected 2 distinct CVEs, got %d: %+v", len(byCve), matches)
	}

	m1 := byCve["CVE-1"]
	parts := strings.Split(m1.Method, ",")
	sort.Strings(parts)
	gotMethod := strings.Join(parts, ",")
	if gotMethod != "crit,purl,version-range:lessThan" {
		t.Fatalf("CVE-1 methods = %q, want all of version-range:lessThan,purl,crit", m1.Method)
	}
	if m1.VulnerableRange != "<2.0.0" {
		t.Fatalf("CVE-1 VulnerableRange = %q, want %q (from version-range)", m1.VulnerableRange, "<2.0.0")
	}

	if byCve["CVE-2"].Method != "purl" {
		t.Fatalf("CVE-2 method = %q, want purl", byCve["CVE-2"].Method)
	}
}

// CPE matching must run only when the dependency carries a CPE.
func TestMatchDependency_CPEGatedOnPresence(t *testing.T) {
	q := &fakeQuerier{
		cpeAffected: [][]any{{"CVE-CPE"}},
	}

	// No CPE → CPE method must not run, so no CVE-CPE.
	noCPE := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm"}
	matches, _ := MatchDependency(context.Background(), q, noCPE)
	if _, ok := methodsByCve(matches)["CVE-CPE"]; ok {
		t.Fatalf("CPE match should not run without a CPE: %+v", matches)
	}

	// With CPE → CVE-CPE appears via the cpe method.
	withCPE := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm", Cpe: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
	matches, _ = MatchDependency(context.Background(), q, withCPE)
	m := methodsByCve(matches)["CVE-CPE"]
	if m.Method != "cpe" {
		t.Fatalf("expected cpe method for CVE-CPE, got %q (%+v)", m.Method, matches)
	}
}

// CRIT only tags CVEs already discovered — it never introduces new ones.
func TestMatchDependency_CritTagsOnly(t *testing.T) {
	q := &fakeQuerier{
		purl: [][]any{{"CVE-A"}},
		crit: [][]any{{"CVE-A"}, {"CVE-ORPHAN"}}, // CVE-ORPHAN not matched by any discovery method
	}
	dep := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/x@1.0.0"}
	matches, _ := MatchDependency(context.Background(), q, dep)
	byCve := methodsByCve(matches)
	if _, ok := byCve["CVE-ORPHAN"]; ok {
		t.Fatalf("crit must not introduce CVE-ORPHAN: %+v", matches)
	}
	if got := byCve["CVE-A"].Method; got != "purl,crit" {
		t.Fatalf("CVE-A method = %q, want purl,crit", got)
	}
}

func TestMatchQueriesFilterInactiveMetadata(t *testing.T) {
	dep := Dependency{
		Name:      "lodash",
		Version:   "1.5.0",
		Ecosystem: "npm",
		Purl:      "pkg:npm/lodash@1.5.0",
		Cpe:       "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*",
		Key:       "k",
	}
	q := &fakeQuerier{}
	_, err := MatchDependency(context.Background(), q, dep)
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(q.queries, "\n")
	for _, want := range []string{
		`JOIN "CVEMetadata"`,
		`NOT IN ('REJECTED', 'WITHDRAWN')`,
		`EXISTS (
		    SELECT 1 FROM "CVEMetadata" cm`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected matcher SQL to contain %q; queries:\n%s", want, joined)
		}
	}
}

// ── wildcard suppression / alias collation ───────────────────────────────────

func cveSet(ms []Match) map[string]Match { return methodsByCve(ms) }

// vr is a version-range fake row: cveId, affectedId, source, status, versionType,
// version, lessThan, lessThanOrEqual, isValidVersion, changes.
func vr(cve, prod, status, version string, lessThan any) []any {
	var v any
	if version != "" {
		v = version
	}
	return []any{cve, prod, "osv", status, "semver", v, lessThan, nil, nil, nil}
}

// Rule 1 (single CVE): a "*" row coexisting with a specific range; installed
// above the range ⇒ the wildcard is discarded and nothing matches.
func TestSuppress_WildcardDroppedWhenSpecific(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{
		vr("CVE-1", "p1", "affected", "*", nil),
		vr("CVE-1", "p1", "affected", "", "2.0.0"),
	}}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	matches, _ := MatchDependency(context.Background(), q, dep)
	if _, ok := cveSet(matches)["CVE-1"]; ok {
		t.Fatalf("CVE-1 wildcard should be suppressed (installed above specific range): %+v", matches)
	}
}

// Rule 2: a "*" that is the ONLY evidence stays a valid all-versions match.
func TestKeep_WildcardOnlyIsValid(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{vr("CVE-2", "p1", "affected", "*", nil)}}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	m := cveSet(MatchDependencyMust(t, q, dep))["CVE-2"]
	if m.CveID != "CVE-2" || m.VulnerableRange != "*" || !strings.Contains(m.Method, "version-range:wildcard") {
		t.Fatalf("CVE-2 should be kept as all-versions wildcard: %+v", m)
	}
}

// A coarse CPE hit is dropped from the method list when version-range supplies
// specific evidence for the same CVE.
func TestSuppress_CoarseCPEWhenSpecific(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{vr("CVE-3", "p1", "affected", "", "6.0.0")},
		cpeAffected:  [][]any{{"CVE-3"}},
	}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm", Cpe: "cpe:2.3:a:v:p:5.0:*:*:*:*:*:*:*"}
	m := cveSet(MatchDependencyMust(t, q, dep))["CVE-3"]
	if m.CveID != "CVE-3" || strings.Contains(m.Method, "cpe") || m.Method != "version-range:lessThan" {
		t.Fatalf("CVE-3 should keep version-range and drop cpe: %+v", m)
	}
}

// Alias collation: "*" on CVE-X + "<2.3.1" on alias GHSA-Y. Installed above the
// range ⇒ both gone (the alias's specific fact suppresses CVE-X's wildcard).
func TestSuppress_AliasGroupAboveRange(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{
			vr("CVE-X", "px", "affected", "*", nil),
			vr("GHSA-Y", "py", "affected", "", "2.3.1"),
		},
		alias: [][]any{{"CVE-X", "GHSA-Y"}},
	}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	matches := MatchDependencyMust(t, q, dep)
	if len(matches) != 0 {
		t.Fatalf("alias group above range should yield no matches, got %+v", matches)
	}
}

// Same alias group, installed inside the range ⇒ GHSA-Y matches (specific),
// CVE-X's wildcard is still suppressed.
func TestSuppress_AliasGroupInRange(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{
			vr("CVE-X", "px", "affected", "*", nil),
			vr("GHSA-Y", "py", "affected", "", "2.3.1"),
		},
		alias: [][]any{{"CVE-X", "GHSA-Y"}},
	}
	dep := Dependency{Name: "x", Version: "2.0.0", Ecosystem: "npm"}
	byCve := cveSet(MatchDependencyMust(t, q, dep))
	if _, ok := byCve["CVE-X"]; ok {
		t.Fatalf("CVE-X wildcard should be suppressed by alias's specific range: %+v", byCve)
	}
	m, ok := byCve["GHSA-Y"]
	if !ok || m.VulnerableRange != "<2.3.1" {
		t.Fatalf("GHSA-Y should match in range with <2.3.1: %+v", byCve)
	}
}

// A version-less PURL is coarse and is suppressed when the CVE has specific
// version evidence the installed version sits outside of.
func TestSuppress_VersionlessPurl(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{vr("CVE-5", "p1", "affected", "", "3.0.0")},
		purl:         [][]any{{"CVE-5"}},
	}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm", Purl: "pkg:npm/x"}
	if _, ok := cveSet(MatchDependencyMust(t, q, dep))["CVE-5"]; ok {
		t.Fatalf("CVE-5 version-less purl should be suppressed by out-of-range specific data")
	}
}

// CRIT runs after suppression and must not resurrect a dropped CVE.
func TestCrit_AfterSuppression(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{
			vr("CVE-6", "p1", "affected", "*", nil),
			vr("CVE-6", "p1", "affected", "", "2.0.0"),
		},
		crit: [][]any{{"CVE-6"}},
	}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	if _, ok := cveSet(MatchDependencyMust(t, q, dep))["CVE-6"]; ok {
		t.Fatalf("crit must not resurrect a suppressed CVE-6")
	}
}

func MatchDependencyMust(t *testing.T, q Querier, dep Dependency) []Match {
	t.Helper()
	m, err := MatchDependency(context.Background(), q, dep)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCPEPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl"},
		{"cpe:2.3:o:linux:linux_kernel:5.0", "cpe:2.3:o:linux:linux_kernel"},
		{"cpe:/a:legacy:uri", ""}, // not 2.3
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := cpePrefix(c.in); got != c.want {
			t.Errorf("cpePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppendMethod(t *testing.T) {
	if got := appendMethod("", "purl"); got != "purl" {
		t.Fatalf("append to empty: %q", got)
	}
	if got := appendMethod("purl", "crit"); got != "purl,crit" {
		t.Fatalf("append new: %q", got)
	}
	if got := appendMethod("purl,crit", "purl"); got != "purl,crit" {
		t.Fatalf("append duplicate should be a no-op: %q", got)
	}
}

// "introduced 0, never fixed" arrives as `0 .. *` from OSV and GitHub, while cve.org
// records the same advisory as a bare exact `0`. The bare 0 is a placeholder for "from
// the beginning", not a specific version, so it must not discard the open range as
// over-broad evidence. Before this, babel-traverse 6.26.0 was missed for
// GHSA-67hx-6x53-jw92 / CVE-2023-45133.
func TestKeep_OpenRangeWhenAliasHasBareZero(t *testing.T) {
	q := &fakeQuerier{
		versionRange: [][]any{
			vr("GHSA-Z", "osv-p", "affected", "0", "*"),
			vr("CVE-Z", "cve-org-p", "affected", "0", nil),
			vr("CVE-Z", "osv-p2", "affected", "0", "*"),
		},
		alias: [][]any{{"CVE-Z", "GHSA-Z"}},
	}
	dep := Dependency{Name: "babel-traverse", Version: "6.26.0", Ecosystem: "npm"}
	byCve := cveSet(MatchDependencyMust(t, q, dep))
	for _, id := range []string{"GHSA-Z", "CVE-Z"} {
		m, ok := byCve[id]
		if !ok || !strings.Contains(m.Method, "version-range:wildcard") {
			t.Fatalf("%s should be kept as an open-ended match: %+v", id, byCve)
		}
	}
}

// A real exact version is still specific evidence: it discards a wildcard the
// installed version sits outside of.
func TestSuppress_RealExactVersionStillSpecific(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{
		vr("CVE-W", "p1", "affected", "*", nil),
		vr("CVE-W", "p2", "affected", "2.0.0", nil),
	}}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	if _, ok := cveSet(MatchDependencyMust(t, q, dep))["CVE-W"]; ok {
		t.Fatal("an exact 2.0.0 is specific evidence; the wildcard should be suppressed at 5.0.0")
	}
}

func TestRowIsZeroPlaceholder(t *testing.T) {
	cases := []struct {
		r    affRow
		want bool
	}{
		{affRow{version: "0"}, true},
		{affRow{version: "0.0.0"}, true},
		{affRow{version: "0", lessThan: "1.2.3"}, false},
		{affRow{version: "0", lessThanOrEqual: "1.2.3"}, false},
		{affRow{version: "0", lessThan: "*"}, false},
		{affRow{version: "1.0.0"}, false},
		{affRow{version: "0.1"}, false},
		{affRow{}, false},
	}
	for _, c := range cases {
		if got := rowIsZeroPlaceholder(c.r); got != c.want {
			t.Errorf("rowIsZeroPlaceholder(%+v) = %v, want %v", c.r, got, c.want)
		}
	}
}

// OSV lists the affected releases beside an open-ended "introduced 0, never fixed"
// range as `versions`. They are the range spelled out, so they must not cancel it:
// MAL-2025-653 (eslint-v9) marks the whole package malicious, and an install that is
// not one of the listed releases is still the malicious package.
func TestKeep_OpenRangeNextToEnumeratedVersions(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{
		vr("MAL-1", "p", "affected", "0", "*"),
		vr("MAL-1", "p", "affected", "9.9.9", nil),
	}}
	dep := Dependency{Name: "eslint-v9", Version: "9.0.0", Ecosystem: "npm"}
	m, ok := cveSet(MatchDependencyMust(t, q, dep))["MAL-1"]
	if !ok || !strings.Contains(m.Method, "version-range:wildcard") {
		t.Fatalf("an open range must survive its own enumerated versions: %+v", m)
	}
}

// A legacy bare "*" is still discarded by an enumerated exact version: that pairing
// says "these releases", not "everything".
func TestSuppress_BareWildcardStillLosesToExactVersion(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{
		vr("CVE-B", "p1", "affected", "*", nil),
		vr("CVE-B", "p2", "affected", "2.0.0", nil),
	}}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	if _, ok := cveSet(MatchDependencyMust(t, q, dep))["CVE-B"]; ok {
		t.Fatal("a bare wildcard must still lose to an exact version")
	}
}

// A bounded range says the package WAS fixed, so it does cancel an open range.
func TestSuppress_OpenRangeLosesToBoundedFix(t *testing.T) {
	q := &fakeQuerier{versionRange: [][]any{
		vr("CVE-F", "p", "affected", "0", "*"),
		vr("CVE-F", "p2", "affected", "", "2.0.0"),
	}}
	dep := Dependency{Name: "x", Version: "5.0.0", Ecosystem: "npm"}
	if _, ok := cveSet(MatchDependencyMust(t, q, dep))["CVE-F"]; ok {
		t.Fatal("an open range must lose to a bounded fix the install sits above")
	}
}
