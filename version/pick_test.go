package version

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func ms(t *testing.T, iso string) *int64 {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t.Fatalf("bad time %q: %v", iso, err)
	}
	v := ts.UnixMilli()
	return &v
}

func cands(t *testing.T, pairs ...string) []Candidate {
	t.Helper()
	var out []Candidate
	for i := 0; i+1 < len(pairs); i += 2 {
		c := Candidate{Version: pairs[i]}
		if pairs[i+1] != "" {
			c.PublishedAtMs = ms(t, pairs[i+1])
		}
		out = append(out, c)
	}
	return out
}

// The bug that started this: "latest" took the newest clean release by date, so
// when the newer lines carried no publish date the old line's point release won.
func TestLatestIgnoresDatesForOrderablePackages(t *testing.T) {
	t.Run("newer versions undated", func(t *testing.T) {
		c := cands(t,
			"0.15.21", "2026-07-09T10:00:00Z",
			"0.15.22", "2026-07-16T10:00:00Z",
			"0.16.0", "",
			"0.17.0", "",
			"0.17.2", "")
		if got := PickLatest("pypi", c); got != "0.17.2" {
			t.Fatalf("latest = %q, want 0.17.2", got)
		}
	})
	t.Run("back-port published after the newest line", func(t *testing.T) {
		c := cands(t,
			"0.15.22", "2026-07-16T10:00:00Z",
			"0.17.0", "2026-10-09T10:00:00Z",
			"0.17.2", "2026-10-22T10:00:00Z",
			"0.15.23", "2026-10-23T10:00:00Z")
		if got := PickLatest("pypi", c); got != "0.17.2" {
			t.Fatalf("latest = %q, want 0.17.2", got)
		}
	})
}

func TestLatestSkipsPrereleases(t *testing.T) {
	c := cands(t,
		"1.0.0", "2026-01-01T00:00:00Z",
		"1.1.0-rc.1", "2026-02-01T00:00:00Z",
		"1.1.0-beta", "2026-01-15T00:00:00Z")
	p := Pick("npm", "1.0.0", c)
	if p.Latest != "1.0.0" || p.Safest != "1.0.0" {
		t.Fatalf("latest/safest = %q/%q, want 1.0.0", p.Latest, p.Safest)
	}
	only := cands(t, "2.0.0-rc.1", "2026-01-01T00:00:00Z", "2.0.0-beta.1", "2026-01-02T00:00:00Z")
	p = Pick("npm", "1.0.0", only)
	if p.Latest != "" || p.Reasons["latest"] != "only-prerelease" {
		t.Fatalf("all pre-release: latest=%q reasons=%v", p.Latest, p.Reasons)
	}
	if p.Stable != "" || p.Reasons["stable"] != "only-prerelease" {
		t.Fatalf("all pre-release: stable=%q reasons=%v", p.Stable, p.Reasons)
	}
	// rolling still offers them
	if !reflect.DeepEqual(p.Rolling, []string{"2.0.0-beta.1"}) {
		t.Fatalf("rolling = %v", p.Rolling)
	}
}

func TestStableIsClosestStableRelease(t *testing.T) {
	c := cands(t,
		"1.4.0", "2026-01-01T00:00:00Z",
		"1.5.2", "2026-02-01T00:00:00Z",
		"1.6.0-rc.1", "2026-03-01T00:00:00Z",
		"2.0.0", "2026-04-01T00:00:00Z")
	if got := PickStable("npm", "1.5.0", c); got != "1.5.2" {
		t.Fatalf("stable = %q, want 1.5.2", got)
	}
	// 1.5.0 is equally far from 1.4.0 and 1.6.0 on minor; the pre-release is
	// skipped and 1.4.0 loses to the higher 1.5.2 on patch distance.
	if got := PickStable("npm", "", c); got != "" {
		t.Fatalf("no running version must give no stable pick, got %q", got)
	}
	// distance ties go to the higher version
	tie := cands(t, "1.4.0", "", "1.6.0", "")
	if got := PickStable("npm", "1.5.0", tie); got != "1.6.0" {
		t.Fatalf("tie = %q, want the higher 1.6.0", got)
	}
}

func TestStableSkipsEcosystemSpecificUnstableForms(t *testing.T) {
	cases := []struct {
		eco, running string
		versions     []string
		want         string
	}{
		{"pypi", "2.0", []string{"2.0.1", "2.1.dev3", "2.1rc1", "2.2a1"}, "2.0.1"},
		{"maven", "1.0", []string{"1.0.1", "1.1-SNAPSHOT", "1.1-M1", "1.1-RC2"}, "1.0.1"},
		{"debian", "1.0-1", []string{"1.0-2", "1.1~rc1-1", "1.1~git20240101-1"}, "1.0-2"},
		{"rubygems", "3.0.0", []string{"3.0.1", "3.1.0.pre", "3.1.0.rc1"}, "3.0.1"},
		{"golang", "v1.2.0", []string{"v1.2.1", "v1.3.0-rc.1", "v1.2.3-20191109021931-daa7c04131f5"}, "v1.2.1"},
	}
	for _, c := range cases {
		var cs []Candidate
		for _, v := range c.versions {
			cs = append(cs, Candidate{Version: v})
		}
		if got := PickStable(c.eco, c.running, cs); got != c.want {
			t.Errorf("%s: stable = %q, want %q", c.eco, got, c.want)
		}
	}
}

func TestRolling(t *testing.T) {
	c := cands(t,
		"1.0.0", "2026-05-04T23:59:59Z",
		"1.1.0", "2026-05-05T00:00:00Z",
		"1.1.1", "2026-05-05T13:00:00Z",
		"1.2.0-rc.1", "2026-05-05T20:00:00Z",
		"0.9.9", "2026-05-05T08:00:00Z",
		"1.1.1", "2026-05-05T14:00:00Z", // duplicate row, later date: still one version
	)
	got, day := PickRolling("npm", c)
	want := []string{"1.2.0-rc.1", "1.1.1", "1.1.0", "0.9.9"}
	if day != "2026-05-05" || !reflect.DeepEqual(got, want) {
		t.Fatalf("rolling = %v on %q, want %v on 2026-05-05", got, day, want)
	}
	if got, day := PickRolling("npm", cands(t, "1.0.0", "", "1.1.0", "")); got != nil || day != "" {
		t.Fatalf("no dates: rolling = %v %q", got, day)
	}
	p := Pick("npm", "1.0.0", cands(t, "1.0.0", ""))
	if p.Reasons["rolling"] != "no-dates" {
		t.Fatalf("reasons = %v", p.Reasons)
	}
}

func TestRollingPrevDay(t *testing.T) {
	c := cands(t,
		"1.0.0", "2026-05-01T10:00:00Z",
		"1.0.1", "2026-05-03T09:00:00Z",
		"1.0.2", "2026-05-03T18:00:00Z",
		"1.1.0", "2026-05-05T00:00:00Z",
		"0.9.9", "2026-05-06T00:00:00Z", // back-port after the anchor day: ignored
	)
	p := Pick("npm", "1.0.0", c)
	if p.RollingDate != "2026-05-05" {
		t.Fatalf("anchor = %q", p.RollingDate)
	}
	if p.RollingPrevDayDate != "2026-05-03" || !reflect.DeepEqual(p.RollingPrevDay, []string{"1.0.2", "1.0.1"}) {
		t.Fatalf("prev day = %v on %q, want [1.0.2 1.0.1] on 2026-05-03", p.RollingPrevDay, p.RollingPrevDayDate)
	}
	if got := PickRollingTarget("npm", "1.0.0", p.RollingPrevDay); got != "1.0.1" {
		t.Fatalf("prev day target = %q, want 1.0.1", got)
	}

	single := Pick("npm", "1.0.0", cands(t, "1.0.0", "2026-05-01T10:00:00Z", "1.0.1", "2026-05-01T12:00:00Z"))
	if single.RollingPrevDay != nil || single.Reasons["rollingPrevDay"] != "no-prior-day" {
		t.Fatalf("single day: %v %v", single.RollingPrevDay, single.Reasons)
	}
	undated := Pick("npm", "1.0.0", cands(t, "1.0.0", "", "1.1.0", ""))
	if undated.Reasons["rollingPrevDay"] != "no-dates" {
		t.Fatalf("undated reasons = %v", undated.Reasons)
	}
}

func TestRollingPrevSemver(t *testing.T) {
	c := cands(t,
		"1.9.0", "2026-05-01T00:00:00Z",
		"1.9.1", "2026-05-02T00:00:00Z",
		"1.9.2", "2026-05-03T00:00:00Z",
		"2.0.0-rc.1", "2026-05-04T00:00:00Z",
		"1.8.7", "2026-05-05T00:00:00Z", // back-port, published last
	)
	p := Pick("npm", "1.8.0", c)
	if p.RollingPrevSemver != "1.9.1" {
		t.Fatalf("prev semver = %q, want 1.9.1", p.RollingPrevSemver)
	}
	// Dates are not needed: a Go module with no publish dates still gets one.
	g := Pick("golang", "v0.17.0", cands(t, "v0.31.0", "", "v0.32.0", "", "v0.33.0", ""))
	if g.RollingPrevSemver != "v0.32.0" || g.RollingDate != "" {
		t.Fatalf("undated go: prev semver = %q, rolling day = %q", g.RollingPrevSemver, g.RollingDate)
	}
	// Exposed releases count, as they do for rolling.
	e := cands(t, "3.0.0", "", "3.0.1", "")
	e[0].Exposed = true
	if got := Pick("npm", "3.0.0", e).RollingPrevSemver; got != "3.0.0" {
		t.Fatalf("exposed prev semver = %q, want 3.0.0", got)
	}
	one := Pick("npm", "1.0.0", cands(t, "1.0.0", ""))
	if one.RollingPrevSemver != "" || one.Reasons["rollingPrevSemver"] != "no-prior-release" {
		t.Fatalf("one release: %q %v", one.RollingPrevSemver, one.Reasons)
	}
}

func TestRollingPrevSemverFallsBackToThePrevDayWhenUnorderable(t *testing.T) {
	c := cands(t,
		"alpha", "2026-05-01T00:00:00Z",
		"bravo", "2026-05-02T00:00:00Z",
		"charlie", "2026-05-03T00:00:00Z")
	p := Pick("npm", "", c)
	if p.Orderable {
		t.Fatal("expected an unorderable package")
	}
	if p.RollingPrevSemver != "bravo" || p.Reasons["rollingPrevSemver"] != "semver-fallback-day" {
		t.Fatalf("prev semver = %q reasons = %v", p.RollingPrevSemver, p.Reasons)
	}
}

func TestRollingTargetIsClosestToRunning(t *testing.T) {
	set := []string{"2.4.1", "2.3.9", "2.4.0-rc.1"}
	if got := PickRollingTarget("npm", "2.3.0", set); got != "2.3.9" {
		t.Fatalf("target = %q, want 2.3.9", got)
	}
	if got := PickRollingTarget("npm", "", set); got != "2.4.1" {
		t.Fatalf("no running version: target = %q, want the highest 2.4.1", got)
	}
	if got := PickRollingTarget("npm", "2.3.0", nil); got != "" {
		t.Fatalf("empty set: %q", got)
	}
}

// A package that moved between calendar versions and ordinary ones cannot be
// ordered by number: 2019.12.1 would outrank 1.2.0. Dates decide.
func TestMixedCalVerAndSemVerFallsBackToDates(t *testing.T) {
	c := cands(t,
		"2019.10.1", "2019-10-01T00:00:00Z",
		"2019.11.2", "2019-11-02T00:00:00Z",
		"2019.12.1", "2019-12-01T00:00:00Z",
		"1.0.0", "2020-03-01T00:00:00Z",
		"1.1.0", "2020-06-01T00:00:00Z",
		"1.2.0", "2020-09-01T00:00:00Z")
	p := Pick("pypi", "", c)
	if p.Orderable {
		t.Fatal("a package that switched between CalVer and SemVer must not be treated as orderable")
	}
	if p.Latest != "1.2.0" {
		t.Fatalf("latest = %q, want the most recent release 1.2.0", p.Latest)
	}
}

func TestPureCalVerIsOrderable(t *testing.T) {
	c := cands(t,
		"2023.11.17", "2023-11-17T00:00:00Z",
		"2024.2.2", "",
		"2024.10.5", "2024-10-05T00:00:00Z",
		"2024.9.30", "2024-09-30T00:00:00Z")
	if p := Pick("pypi", "", c); !p.Orderable || p.Latest != "2024.10.5" {
		t.Fatalf("orderable=%v latest=%q", p.Orderable, p.Latest)
	}
}

func TestUnorderableFallsBackToRecency(t *testing.T) {
	c := cands(t,
		"alpha-one", "2026-01-01T00:00:00Z",
		"beta-two", "2026-03-01T00:00:00Z",
		"gamma-three", "2026-02-01T00:00:00Z",
		"v1", "")
	// the generic scheme cannot order these, so the newest dated release wins
	p := Pick("someunknownecosystem", "", c)
	if p.Orderable {
		t.Fatal("must not be orderable")
	}
}

func TestNoCandidates(t *testing.T) {
	p := Pick("npm", "1.0.0", nil)
	if p.Latest != "" || p.Stable != "" || p.Rolling != nil || p.Reasons["latest"] != "no-candidates" {
		t.Fatalf("%+v", p)
	}
}

func TestRollingCodec(t *testing.T) {
	enc, err := EncodeRolling([]string{"1.2.0-rc.1", "1.1.1", "2:1.0-1ubuntu0.22.04.1", "1.0~rc1"})
	if err != nil {
		t.Fatal(err)
	}
	if enc != "1.2.0-rc.1,1.1.1,2:1.0-1ubuntu0.22.04.1,1.0~rc1" {
		t.Fatalf("encoded = %q", enc)
	}
	dec, err := DecodeRolling(enc)
	if err != nil || strings.Join(dec, ",") != enc {
		t.Fatalf("decoded = %v err=%v", dec, err)
	}
	for _, bad := range []string{"1.0,1", "1.0 1", "<1.0", "1.*", "a|b", ""} {
		if _, err := EncodeRolling([]string{"1.0.0", bad}); err == nil {
			t.Errorf("EncodeRolling accepted %q", bad)
		}
	}
	dec, err = DecodeRolling(" 1.0.0 ,, 1.0.0,2.0.0,")
	if err != nil || !reflect.DeepEqual(dec, []string{"1.0.0", "2.0.0"}) {
		t.Fatalf("lenient decode = %v err=%v", dec, err)
	}
	if _, err := DecodeRolling("1.0.0,>=2"); err == nil {
		t.Error("DecodeRolling accepted a range")
	}
	if dec, err := DecodeRolling(""); err != nil || len(dec) != 0 {
		t.Errorf("empty = %v %v", dec, err)
	}
}

// Rolling is the safer rolling: the most recent release day with malware gone
// (the caller drops it), but exposed releases stay. Latest, safest and stable
// never see an exposed release.
func TestRollingKeepsExposedReleasesOthersSkipThem(t *testing.T) {
	c := cands(t,
		"1.0.0", "2026-05-01T10:00:00Z",
		"1.1.0", "2026-05-02T10:00:00Z",
		"1.2.0", "2026-05-09T10:00:00Z",
		"1.2.1", "2026-05-09T12:00:00Z",
	)
	c[0].Exposed = true // the running version is itself vulnerable
	c[2].Exposed = true
	c[3].Exposed = true
	p := Pick("npm", "1.0.0", c)
	if want := []string{"1.2.1", "1.2.0"}; !reflect.DeepEqual(p.Rolling, want) || p.RollingDate != "2026-05-09" {
		t.Fatalf("rolling = %v on %q, want %v on 2026-05-09", p.Rolling, p.RollingDate, want)
	}
	if p.Latest != "1.1.0" || p.Safest != "1.1.0" || p.Stable != "1.1.0" {
		t.Fatalf("clean picks drew on exposed releases: %+v", p)
	}
	if got := PickLatest("npm", c); got != "1.1.0" {
		t.Fatalf("PickLatest = %q", got)
	}
	if got := PickStable("npm", "1.0.0", c); got != "1.1.0" {
		t.Fatalf("PickStable = %q", got)
	}
	if got, _ := PickRolling("npm", c); !reflect.DeepEqual(got, []string{"1.2.1", "1.2.0"}) {
		t.Fatalf("PickRolling = %v", got)
	}
}

// When every release is exposed there is still a rolling set, and the clean
// outcomes are empty with a reason.
func TestRollingWhenNothingIsClean(t *testing.T) {
	c := cands(t, "2.0.0", "2026-06-01T00:00:00Z")
	c[0].Exposed = true
	p := Pick("npm", "1.0.0", c)
	if !reflect.DeepEqual(p.Rolling, []string{"2.0.0"}) || p.Latest != "" || p.Reasons["latest"] != "no-candidates" {
		t.Fatalf("picks = %+v", p)
	}
}

// Rolling follows the same two steps as latest: version order, then date. A
// point release on an old branch published after the highest version does not
// move the rolling day.
func TestRollingAnchorsOnTheHighestVersionThenItsDate(t *testing.T) {
	c := cands(t,
		"0.15.21", "2026-07-09T20:00:00Z",
		"0.17.0", "2026-07-30T19:00:00Z",
		"0.17.1rc1", "2026-07-30T22:00:00Z", // a pre-release counts
		"0.15.22", "2026-08-02T10:00:00Z", // back-port, newest by date
	)
	c[1].Exposed = true // a vulnerable version still anchors rolling
	got, day := PickRolling("pypi", c)
	if want := []string{"0.17.1rc1", "0.17.0"}; day != "2026-07-30" || !reflect.DeepEqual(got, want) {
		t.Fatalf("rolling = %v on %q, want %v on 2026-07-30", got, day, want)
	}
	p := Pick("pypi", "0.15.10", c)
	if !reflect.DeepEqual(p.Rolling, []string{"0.17.1rc1", "0.17.0"}) || p.RollingDate != "2026-07-30" {
		t.Fatalf("Pick rolling = %v on %q", p.Rolling, p.RollingDate)
	}
}

// A package no scheme can order has no highest version, so the most recent day
// stands, as it does for latest.
func TestRollingFallsBackToTheNewestDayWhenUnorderable(t *testing.T) {
	c := cands(t,
		"stable", "2026-01-01T00:00:00Z",
		"edge", "2026-03-01T00:00:00Z",
		"nightly-20260302", "2026-03-02T00:00:00Z",
	)
	got, day := PickRolling("docker", c)
	if day != "2026-03-02" || !reflect.DeepEqual(got, []string{"nightly-20260302"}) {
		t.Fatalf("rolling = %v on %q", got, day)
	}
}

// The highest version has no release date, so it cannot place a day: the highest
// dated version does.
func TestRollingSkipsAnUndatedHighestVersion(t *testing.T) {
	c := cands(t,
		"1.0.0", "2026-01-01T00:00:00Z",
		"1.1.0", "2026-02-01T00:00:00Z",
		"1.2.0", "",
		"0.9.0", "2026-03-01T00:00:00Z",
	)
	got, day := PickRolling("npm", c)
	if day != "2026-02-01" || !reflect.DeepEqual(got, []string{"1.1.0"}) {
		t.Fatalf("rolling = %v on %q, want [1.1.0] on 2026-02-01", got, day)
	}
}

// Parity keeps a migrated package as close as possible to what runs today, by
// the distribution's own order, revision included.
func TestParity(t *testing.T) {
	cases := []struct {
		name, eco, running string
		have               []string
		want               string
	}{
		{"apk: the next rebuild of the same release", "alpine", "1.36.1-r15", []string{"1.36.1-r29", "1.36.1-r31", "1.37.0-r0"}, "1.36.1-r29"},
		{"apk: an exact match wins", "alpine", "8.9.1-r1", []string{"8.9.1-r1", "8.11.0-r2"}, "8.9.1-r1"},
		{"apk: nothing above, take the nearest below", "alpine", "3.12.8-r0", []string{"3.11.9-r0", "3.12.7-r0"}, "3.12.7-r0"},
		{"deb: epoch and revision ordered", "debian", "1:2.39.2-1", []string{"1:2.39.2-1+deb12u1", "1:2.39.5-0+deb12u1", "2.45.0-1"}, "1:2.39.2-1+deb12u1"},
		{"rpm: release compared", "redhat", "3.0.7-25.el9", []string{"3.0.7-27.el9", "3.0.7-28.el9", "3.2.2-6.el9"}, "3.0.7-27.el9"},
		{"arch: pkgrel compared", "arch", "8.9.1-1", []string{"8.9.1-2", "8.10.0-1"}, "8.9.1-2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var cs []Candidate
			for _, v := range c.have {
				cs = append(cs, Candidate{Version: v})
			}
			if got := PickParity(c.eco, c.running, cs); got != c.want {
				t.Fatalf("PickParity(%s, %s) = %q, want %q", c.eco, c.running, got, c.want)
			}
			if got := Pick(c.eco, c.running, cs).Parity; got != c.want {
				t.Fatalf("Pick(...).Parity = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParityTakesExposedReleases(t *testing.T) {
	cs := []Candidate{{Version: "1.36.1-r29", Exposed: true}, {Version: "1.36.1-r31"}}
	if got := PickParity("alpine", "1.36.1-r15", cs); got != "1.36.1-r29" {
		t.Fatalf("parity is not a safety pick; got %q", got)
	}
}

func TestParityReasons(t *testing.T) {
	if p := Pick("alpine", "", []Candidate{{Version: "1.0-r0"}}); p.Parity != "" || p.Reasons["parity"] != "no-running-version" {
		t.Fatalf("no running version: %+v", p)
	}
	if p := Pick("alpine", "1.0-r0", nil); p.Parity != "" || p.Reasons["parity"] != "no-candidates" {
		t.Fatalf("no candidates: %+v", p)
	}
}
