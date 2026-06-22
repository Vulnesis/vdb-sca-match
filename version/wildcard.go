package version

import "strings"

// IsFullWildcard reports whether s is a bare "all versions" token ("*", "x").
func IsFullWildcard(s string) bool {
	s = strings.TrimSpace(s)
	return s == "*" || s == "x" || s == "X"
}

// IsSegmentWildcard reports whether pattern contains a wildcard SEGMENT
// ("8.x", "1.2.*") — a dot-separated part that is *, x, or X — while NOT being
// a bare full wildcard.
func IsSegmentWildcard(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || IsFullWildcard(pattern) {
		return false
	}
	for _, p := range strings.Split(stripV(pattern), ".") {
		if p == "*" || p == "x" || p == "X" {
			return true
		}
	}
	return false
}

// MatchSegmentWildcard reports whether installed satisfies a segment-wildcard
// pattern by prefix: the leading non-wildcard segments of pattern must equal the
// corresponding segments of installed ("8.x" matches "8.3.1" but not "9.0.0").
// The second return is true when pattern IS a segment wildcard (so callers can
// distinguish "no match" from "not applicable").
func MatchSegmentWildcard(installed, pattern string) (matched bool, isSegWild bool) {
	if !IsSegmentWildcard(pattern) {
		return false, false
	}
	pp := strings.Split(stripV(pattern), ".")
	ip := strings.Split(stripV(installed), ".")
	for i, seg := range pp {
		if seg == "*" || seg == "x" || seg == "X" {
			return true, true // reached the wildcard segment — prefix matched so far
		}
		if i >= len(ip) {
			return false, true
		}
		if ip[i] == seg {
			continue
		}
		// tolerate leading-zero numeric equality ("08" == "8")
		if a, aok := atoiSeg(ip[i]); aok {
			if b, bok := atoiSeg(seg); bok && a == b {
				continue
			}
		}
		return false, true
	}
	return true, true
}

func stripV(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	return s
}

func atoiSeg(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
