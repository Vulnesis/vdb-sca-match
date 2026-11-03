package version

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0", "1.0.1", -1, true},
		{"1.0.1", "1.0.0", 1, true},
		{"2.0.0", "1.9.9", 1, true},
		{"v1.6.3", "v1.7.0", -1, true},
		{"4.17.20", "4.17.21", -1, true},
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"", "1.0.0", 0, false},
		{"latest", "1.0.0", 0, false},
		{"*", "1.0.0", 0, false},
	}
	for _, c := range cases {
		got, ok := Compare("npm", "semver", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0.post1", "1.0.0", 1, true},
		{"1.0.0a1", "1.0.0", -1, true},
		{"2.0.0", "1.9.9", 1, true},
	}
	for _, c := range cases {
		got, ok := Compare("pypi", "pep440", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareMaven(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0-SNAPSHOT", "1.0", -1, true},
		{"1.0", "1.0-SNAPSHOT", 1, true},
		{"2.0", "1.9", 1, true},
	}
	for _, c := range cases {
		got, ok := Compare("maven", "maven", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareGeneric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"2.0", "1.9", 1},
		{"1.0-1", "1.0-2", -1},
		// A number with a letter suffix is ordered by its number first.
		{"2.37.2", "2.11n", 1},
		{"2.11", "2.11n", -1},
		{"1.0.2k", "1.0.2m", -1},
		{"1.0.2", "1.0.2k", -1},
		{"1.0.10", "1.0.2k", 1},
		{"1.0rc1", "1.0", -1},
		{"2.0b2", "2.0", -1},
	}
	for _, c := range cases {
		got, ok := Compare("deb", "", c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q,%q) ok=false want true", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		version, lower, lt, lte string
		want                    bool
	}{
		{"1.5.0", "1.0.0", "2.0.0", "", true},
		{"2.5.0", "1.0.0", "2.0.0", "", false},
		{"1.0.0", "1.0.0", "", "2.0.0", true},
		{"2.0.0", "1.0.0", "", "2.0.0", true},
		{"2.1.0", "1.0.0", "", "2.0.0", false},
		{"1.5.0", "", "2.0.0", "", true},
		{"1.5.0", "", "", "2.0.0", true},
		{"0.5.0", "1.0.0", "2.0.0", "", false},
	}
	for _, c := range cases {
		got, _ := Within("npm", "semver", c.version, c.lower, c.lt, c.lte)
		if got != c.want {
			t.Errorf("Within(%q, %q, %q, %q)=%v want %v", c.version, c.lower, c.lt, c.lte, got, c.want)
		}
	}
}

// TestWithinPEP440 covers the pypi/django-shaped ranges that had zero coverage:
// real django advisory bounds, patch-in-line, prerelease ordering, and the
// OSV introduced="" (unbounded lower) convention.
func TestWithinPEP440(t *testing.T) {
	cases := []struct {
		name                    string
		version, lower, lt, lte string
		want                    bool
	}{
		{"4.2.16 in [4.2,4.2.17)", "4.2.16", "4.2", "4.2.17", "", true},
		{"4.2.17 fixed, excluded", "4.2.17", "4.2", "4.2.17", "", false},
		{"4.2.1 in [4.2.0,4.2.17)", "4.2.1", "4.2.0", "4.2.17", "", true},
		{"5.0.9 in [5.0,5.0.10)", "5.0.9", "5.0", "5.0.10", "", true},
		{"5.0.10 fixed, excluded", "5.0.10", "5.0", "5.0.10", "", false},
		{"5.1.3 in [5.1,5.1.4)", "5.1.3", "5.1", "5.1.4", "", true},
		{"3.2.25 below 4.2 line", "3.2.25", "4.2", "4.2.17", "", false},
		{"unbounded lower <4.2.20", "4.2.19", "", "4.2.20", "", true},
		{"prerelease 6.0rc1 < 6.0 lower", "6.0rc1", "6.0", "6.0.5", "", false},
		{"prerelease 6.1b1 in [6.0,6.2)", "6.1b1", "6.0", "6.2", "", true},
	}
	for _, c := range cases {
		got, ok := Within("pypi", "pep440", c.version, c.lower, c.lt, c.lte)
		if !ok {
			t.Errorf("%s: Within returned ok=false (unparsed PEP 440)", c.name)
			continue
		}
		if got != c.want {
			t.Errorf("%s: Within(pypi,%q,%q,%q,%q)=%v want %v", c.name, c.version, c.lower, c.lt, c.lte, got, c.want)
		}
	}
}

// A bound that is not valid semver (a four-part gem version) used to be compared as a
// string, so "1.19.4" < "1.6.7.1" and nokogiri 1.19.4 matched a range ending at 1.6.7.1.
func TestWithinOrdersFourPartVersionsNumerically(t *testing.T) {
	cases := []struct {
		version, lower, lt string
		wantIn, wantOK     bool
	}{
		{"1.19.4", "1.6.0", "1.6.7.1", false, true},
		{"1.6.7.0", "1.6.0", "1.6.7.1", true, true},
		{"1.6.7.1", "1.6.0", "1.6.7.1", false, true},
		{"1.5.9", "1.6.0.rc1", "1.6.7.1", false, true},
		{"1.6.0.rc2", "1.6.0.rc1", "1.6.7.1", true, true},
	}
	for _, c := range cases {
		in, ok := Within("rubygems", "semver", c.version, c.lower, c.lt, "")
		if in != c.wantIn || ok != c.wantOK {
			t.Errorf("Within(%s in [%s,%s)) = (%v,%v), want (%v,%v)", c.version, c.lower, c.lt, in, ok, c.wantIn, c.wantOK)
		}
	}
}

// What cannot be parsed at all is inconclusive, never ordered as text.
func TestWithinNeverOrdersAnUnparseableBoundAsText(t *testing.T) {
	in, ok := Within("npm", "semver", "1.19.4", "", "a060c15ef87e0f0e72974c7c0e57fe811bbd06a2", "")
	if in || ok {
		t.Fatalf("a git commit bound is inconclusive, got (%v,%v)", in, ok)
	}
}

// genericSegmentCorpus is the shared corpus for the ordering property tests:
// numeric, alpha, empty, mixed, leading-zero, and int64-overflowing numeric
// segments (parseNumeric returns ok=false for those, so the numeric path is skipped).
func genericSegmentCorpus() []string {
	return []string{
		"", "0", "1", "2", "9", "10", "999",
		"00", "01", "007",
		"9223372036854775807",     // max int64
		"9223372036854775808",     // max int64 + 1, overflows
		"99999999999999999999999", // overflows int64
		"a", "b", "z", "A", "B", "alpha", "beta", "rc", "RC",
		"1a", "a1", "0a", "1a2", "12a34",
	}
}

// TestCompareSegmentAntisymmetry checks the generic per-segment ordering is
// reflexive, antisymmetric, and always in {-1,0,1}.
func TestCompareSegmentAntisymmetry(t *testing.T) {
	for _, a := range genericSegmentCorpus() {
		if got := compareSegment(a, a); got != 0 {
			t.Errorf("compareSegment(%q,%q)=%d, want 0", a, a, got)
		}
		for _, b := range genericSegmentCorpus() {
			ab := compareSegment(a, b)
			if ab < -1 || ab > 1 {
				t.Errorf("compareSegment(%q,%q)=%d, want value in {-1,0,1}", a, b, ab)
			}
			if ab != -compareSegment(b, a) {
				t.Errorf("compareSegment(%q,%q)=%d but compareSegment(%q,%q)=%d; not antisymmetric",
					a, b, ab, b, a, compareSegment(b, a))
			}
		}
	}
}

// genericVersionCorpus builds whole version strings from the segment corpus plus
// compound versions of mixed lengths and kinds (including uneven lengths, which
// exercise the empty-segment special cases).
func genericVersionCorpus() []string {
	versions := []string{""}
	versions = append(versions, genericSegmentCorpus()...)
	versions = append(versions,
		"1.0", "1.0.0", "1.0.1", "2.0", "1.9", "0.0.0", "0.0.0.0.0",
		"1.0-1", "1.0-2", "1.0.1-alpha", "1.0.1-alpha.1", "1.0.0-rc1",
		"1.0.0+build", "1.0.0-alpha+001", "1.2.3.4",
		"007.1", "99999999999999999999999.0", "1.alpha", "alpha.1",
		"1.1a", "10.0", "9.0",
	)
	return versions
}

// segmentSequencesEqual reports whether two version strings split into segment
// sequences that are elementwise equal under compareSegment (missing trailing
// segments compare as ""), the condition compareGeneric's zero result encodes.
func segmentSequencesEqual(a, b string) bool {
	sa := splitVersion(a)
	sb := splitVersion(b)
	maxLen := len(sa)
	if len(sb) > maxLen {
		maxLen = len(sb)
	}
	for i := 0; i < maxLen; i++ {
		var pa, pb string
		if i < len(sa) {
			pa = sa[i]
		}
		if i < len(sb) {
			pb = sb[i]
		}
		if compareSegment(pa, pb) != 0 {
			return false
		}
	}
	return true
}

// TestCompareGenericTotalOrder checks the generic fallback is a total preorder
// over the corpus: always parseable, reflexive, antisymmetric, always in
// {-1,0,1}, and a zero result means the split segment sequences are elementwise
// equal under compareSegment.
func TestCompareGenericTotalOrder(t *testing.T) {
	for _, a := range genericVersionCorpus() {
		if ab, ok := compareGeneric(a, a); !ok || ab != 0 {
			t.Errorf("compareGeneric(%q,%q)=(%d,%v), want (0,true)", a, a, ab, ok)
		}
		for _, b := range genericVersionCorpus() {
			ab, okAB := compareGeneric(a, b)
			if !okAB {
				t.Errorf("compareGeneric(%q,%q) ok=false, want true", a, b)
				continue
			}
			if ab < -1 || ab > 1 {
				t.Errorf("compareGeneric(%q,%q)=%d, want value in {-1,0,1}", a, b, ab)
			}
			ba, okBA := compareGeneric(b, a)
			if !okBA {
				t.Errorf("compareGeneric(%q,%q) ok=false, want true", b, a)
				continue
			}
			if ab != -ba {
				t.Errorf("compareGeneric(%q,%q)=%d but compareGeneric(%q,%q)=%d; not antisymmetric",
					a, b, ab, b, a, ba)
			}
			if ab == 0 && !segmentSequencesEqual(a, b) {
				t.Errorf("compareGeneric(%q,%q)=0 but segments differ under compareSegment", a, b)
			}
		}
	}
}

// TestCompareGenericTransitive completes the total-preorder claim above:
// a<=b and b<=c must give a<=c, and a==b, b==c must give a==c. Overflowing
// numeric segments fall into the lexical branch, which is where a broken
// ordering would show up first.
func TestCompareGenericTransitive(t *testing.T) {
	corpus := genericVersionCorpus()
	cmp := make(map[[2]string]int, len(corpus)*len(corpus))
	for _, a := range corpus {
		for _, b := range corpus {
			c, _ := compareGeneric(a, b)
			cmp[[2]string{a, b}] = c
		}
	}
	for _, a := range corpus {
		for _, b := range corpus {
			ab := cmp[[2]string{a, b}]
			if ab > 0 {
				continue
			}
			for _, c := range corpus {
				bc := cmp[[2]string{b, c}]
				if bc > 0 {
					continue
				}
				ac := cmp[[2]string{a, c}]
				if ac > 0 {
					t.Errorf("not transitive: %q<=%q and %q<=%q but compareGeneric(%q,%q)=%d", a, b, b, c, a, c, ac)
				}
				if ab == 0 && bc == 0 && ac != 0 {
					t.Errorf("equality not transitive: %q==%q==%q but compareGeneric(%q,%q)=%d", a, b, c, a, c, ac)
				}
			}
		}
	}
}

func TestWithinUsesTheDistributionScheme(t *testing.T) {
	for _, tc := range []struct {
		eco, v, lt string
		want       bool
	}{
		{"alpine", "1.2.5-r12", "1.2.5-r9", false},
		{"alpine", "1.2.5-r8", "1.2.5-r9", true},
		{"debian", "1:2.36-9+deb12u10", "1:2.36-9+deb12u9", false},
		{"debian", "2.36-9+deb12u4", "2.36-9+deb12u10", true},
		{"debian", "1.34+dfsg-1.2+deb12u1", "1.34+dfsg-1.2+deb12u1", false},
		{"redhat", "3.0.7-27.el9", "3.0.7-3.el9", false},
	} {
		got, _ := Within(tc.eco, "ECOSYSTEM", tc.v, "", tc.lt, "")
		if got != tc.want {
			t.Errorf("Within(%s, %s < %s) = %v, want %v", tc.eco, tc.v, tc.lt, got, tc.want)
		}
	}
}

// An Arch package version is ordered by libalpm's vercmp, not by splitting on
// dots and dashes: the epoch outranks the version, and pkgrel breaks a tie.
func TestWithinUsesLibalpmForArch(t *testing.T) {
	cases := []struct {
		version, lessThan string
		want              bool
	}{
		{"9.0.1224-1", "9.0.1225-1", true},
		{"9.0.1225-1", "9.0.1225-1", false},
		{"9.0.1225-1", "9.0.1225-2", true},
		{"1.3.1-2", "1:1.0-1", true},
		{"1:1.0-1", "1.3.1-2", false},
		{"6.12.1.arch1-1", "6.12.2.arch1-1", true},
	}
	for _, c := range cases {
		got, ok := Within("arch", "", c.version, "", c.lessThan, "")
		if !ok || got != c.want {
			t.Errorf("Within(arch, %q < %q) = %v, %v; want %v", c.version, c.lessThan, got, ok, c.want)
		}
	}
}

// An Amazon Linux build is ordered by rpm's vercmp with the epoch first, and
// the .amzn2023.0.N dist tag is part of the release: 0.10 is after 0.9.
func TestWithinUsesRpmForAmazon(t *testing.T) {
	cases := []struct {
		version, lessThan string
		want              bool
	}{
		{"3.0.8-1.amzn2023.0.1", "3.0.8-1.amzn2023.0.5", true},
		{"3.0.8-1.amzn2023.0.5", "3.0.8-1.amzn2023.0.5", false},
		{"3.0.8-1.amzn2023.0.10", "3.0.8-1.amzn2023.0.9", false},
		{"3.0.8-1.amzn2023.0.1", "3.2.2-1.amzn2023.0.1", true},
		{"3.0.8-1.amzn2023.0.1", "1:3.0.8-1.amzn2023.0.1", true},
		{"1:3.0.8-1.amzn2023.0.1", "3.2.2-1.amzn2023.0.1", false},
		{"1:3.2.2-1.amzn2023.0.1", "1:3.2.2-1.amzn2023.0.2", true},
		{"6.1.19-30.43.amzn2023", "6.1.25-37.47.amzn2023", true},
	}
	for _, c := range cases {
		got, ok := Within("amazon", "rpm", c.version, "", c.lessThan, "")
		if !ok || got != c.want {
			t.Errorf("Within(amazon, %q < %q) = %v, %v; want %v", c.version, c.lessThan, got, ok, c.want)
		}
	}
}
