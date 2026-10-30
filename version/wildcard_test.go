package version

import "testing"

// segmentExamples pins the boundary between full wildcards and segment
// wildcards, plus a few leading-zero and dot-edge spellings.
var segmentExamples = []struct {
	pattern   string
	installed string
	matched   bool
	wantSeg   bool
}{
	{"8.x", "8.3.1", true, true},
	{"8.x", "9.0.0", false, true},
	{"1.2.*", "1.2.9", true, true},
	{"1.2.*", "1.3.0", false, true},
	{"v8.0.x", "8.0.5", true, true},
	{"V8.0.X", "08.0.5", true, true},
	{"", "1.2.3", false, false},
	{"*", "1.2.3", false, false},
	{"x", "1.2.3", false, false},
	{"X", "1.2.3", false, false},
	{"8.3.1", "8.3.1", false, false},
	{"8.x", "", false, true},
	{"1.2.3.x", "1.2", false, true},
	{"1.2.x", "1", false, true},
	{"1.2.x", "1.", false, true},
	{".8.x", "8.3.1", false, true},
	{"08.x", "8.3.1", true, true},
	{"8.x.", "8.3.1", true, true},
}

func TestIsSegmentWildcardExamples(t *testing.T) {
	// IsSegmentWildcard must reject full wildcards and bare segments and
	// accept patterns with a wildcard segment.
	cases := []struct {
		pattern string
		want    bool
	}{
		{"*", false},
		{"x", false},
		{"", false},
		{"8.x", true},
		{"1.2.*", true},
		{"8.3.1", false},
	}
	for _, c := range cases {
		if got := IsSegmentWildcard(c.pattern); got != c.want {
			t.Errorf("IsSegmentWildcard(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestMatchSegmentWildcardNoPanic(t *testing.T) {
	corpus := []string{
		"", "*", "x", "X", "8.x", "1.2.*", "v8.0.x", "V8.0.X",
		"8", "08", "8.", ".8", "8..x", "..", "1.2.3.4.5.6",
		"1.2", "1", "1.2.3", "1.2.3.4", "abc", "8.abc", "abc.x",
		"08.x", "x.8", "8.x.", ".8.x", "8.0.x", " 8.x ", " 8 . x ",
		"9.0.0", "1.3.0", "v1.2.3", "V1.2.3",
	}
	for _, installed := range corpus {
		for _, pattern := range corpus {
			matched, isSegWild := MatchSegmentWildcard(installed, pattern)
			wantSeg := IsSegmentWildcard(pattern)
			if isSegWild != wantSeg {
				t.Errorf("MatchSegmentWildcard(%q, %q) isSegWild = %v, want %v",
					installed, pattern, isSegWild, wantSeg)
			}
			if matched && !isSegWild {
				t.Errorf("MatchSegmentWildcard(%q, %q) matched a pattern that is not a segment wildcard",
					installed, pattern)
			}
		}
	}
}

func TestMatchSegmentWildcardExamples(t *testing.T) {
	for _, c := range segmentExamples {
		matched, isSegWild := MatchSegmentWildcard(c.installed, c.pattern)
		if isSegWild != c.wantSeg {
			t.Errorf("MatchSegmentWildcard(%q, %q) isSegWild = %v, want %v",
				c.installed, c.pattern, isSegWild, c.wantSeg)
		}
		if matched != c.matched {
			t.Errorf("MatchSegmentWildcard(%q, %q) matched = %v, want %v",
				c.installed, c.pattern, matched, c.matched)
		}
	}
}
