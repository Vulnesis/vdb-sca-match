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
		if numericSegEqual(ip[i], seg) {
			continue
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

// numericSegEqual reports whether a and b are both all-digit segments naming
// the same number, ignoring leading zeros ("08" == "8", "00" == "0"). It
// compares digit strings rather than parsed integers, so segments too long for
// an int cannot wrap around and compare equal to a small number.
func numericSegEqual(a, b string) bool {
	if !allDigits(a) || !allDigits(b) {
		return false
	}
	return trimLeadingZeros(a) == trimLeadingZeros(b)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func trimLeadingZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}
