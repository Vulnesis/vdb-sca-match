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
