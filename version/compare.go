package version

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
	pep440 "github.com/aquasecurity/go-pep440-version"
	mvn "github.com/masahiro331/go-mvn-version"
)

// Compare compares two versions under the given ecosystem/versionType scheme.
// Returns cmp ∈ {-1,0,1} and ok=true when parsing succeeded.
// ok=false means "unparseable under this scheme" — caller must fall back to
// exact string match (precision over recall).
func Compare(ecosystem, versionType, a, b string) (cmp int, ok bool) {
	return compareWithScheme(pickScheme(versionType, ecosystem), a, b)
}

// distroSchemes are the registered distribution schemes pickScheme hands a
// distribution ecosystem to. The generic comparison splits 1.2.5-r12 into
// 1, 2, 5, "r12" and orders "r12" before "r9" as text, so musl 1.2.5-r12 on
// Alpine 3.21 read as below Alpine's fix at 1.2.5-r9.
var distroSchemes = map[string]bool{"debian": true, "rpm": true, "alpine": true, "wolfi": true, "arch": true}

// Within checks if version is inside the range [lowerBound, upperBound).
// The upper bound is exclusive (lessThan) unless lessThanOrEqual is provided.
func Within(ecosystem, versionType, version, lowerBound, lessThan, lessThanOrEqual string) (inRange bool, ok bool) {
	if version == "" {
		return false, false
	}

	scheme := pickScheme(versionType, ecosystem)

	// Check lower bound
	lowerUnparsed := false
	if lowerBound != "" {
		cmp, parsed := compareWithScheme(scheme, version, lowerBound)
		if parsed && cmp < 0 {
			return false, true
		}
		// Unparseable: say so. Comparing the strings ("1.19.4" < "1.6.7.1") is not
		// an ordering of versions, so the answer below can only be inconclusive.
		lowerUnparsed = !parsed
	}

	// Check lessThan upper bound (exclusive)
	if lessThan != "" {
		cmp, parsed := compareWithScheme(scheme, version, lessThan)
		if parsed && cmp < 0 {
			return true, !lowerUnparsed
		}
		// Unparseable bound: inconclusive, never a string comparison.
		return false, parsed
	}

	// Check lessThanOrEqual upper bound (inclusive)
	if lessThanOrEqual != "" {
		cmp, parsed := compareWithScheme(scheme, version, lessThanOrEqual)
		if parsed && cmp <= 0 {
			return true, !lowerUnparsed
		}
		// Unparseable bound: inconclusive, never a string comparison.
		return false, parsed
	}

	// No upper bound — if we got here, lower bound passed
	return lowerBound != "", !lowerUnparsed
}

func pickScheme(versionType, ecosystem string) string {
	vt := strings.ToLower(versionType)
	if vt == "semver" || vt == "npm" || vt == "cargo" || vt == "golang" || vt == "nuget" || vt == "composer" || vt == "hex" || vt == "pub" || vt == "swift" {
		return "semver"
	}
	if vt == "pep440" || vt == "python" || vt == "pypi" {
		return "pep440"
	}
	if vt == "maven" || vt == "java" {
		return "maven"
	}

	eco := strings.ToLower(ecosystem)
	switch eco {
	case "npm", "cargo", "golang", "go", "nuget", "composer", "hex", "pub", "swift":
		return "semver"
	case "pypi", "pip", "python":
		return "pep440"
	case "maven", "java":
		return "maven"
	default:
		if s := SchemeFor(eco); distroSchemes[s] {
			return s
		}
		return "generic"
	}
}

func compareWithScheme(scheme, a, b string) (int, bool) {
	switch scheme {
	case "semver":
		return compareSemver(a, b)
	case "pep440":
		return comparePEP440(a, b)
	case "maven":
		return compareMaven(a, b)
	}
	if distroSchemes[scheme] {
		// A bound that is not a version of the distribution (an upstream
		// "1.35" in a distribution row) keeps the old generic answer.
		if c, ok := CompareScheme(scheme, a, b); ok {
			return c, true
		}
	}
	return compareGeneric(a, b)
}

// ── Semver (Masterminds/semver/v3) ──────────────────────────────────────────

func compareSemver(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}
	va, err := semver.NewVersion(normalizeSemver(a))
	if err != nil {
		return compareSegments(a, b)
	}
	vb, err := semver.NewVersion(normalizeSemver(b))
	if err != nil {
		return compareSegments(a, b)
	}
	return va.Compare(vb), true
}

// compareSegments orders two versions that are not valid semver (a four-part gem
// version like 1.6.7.1, a .rc suffix) by numeric segments. Only a version made of
// dotted segments can be ordered this way; anything else is not comparable.
func compareSegments(a, b string) (int, bool) {
	if !segmentedVersion(a) || !segmentedVersion(b) {
		return 0, false
	}
	return compareGeneric(normalizeSemver(a), normalizeSemver(b))
}

func segmentedVersion(v string) bool {
	v = normalizeSemver(strings.TrimSpace(v))
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-', r == '+', r == '_':
		default:
			return false
		}
	}
	return true
}

func normalizeSemver(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

// ── PEP 440 (aquasecurity/go-pep440-version) ────────────────────────────────

func comparePEP440(a, b string) (int, bool) {
	va, err := pep440.Parse(a)
	if err != nil {
		return 0, false
	}
	vb, err := pep440.Parse(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// ── Maven (masahiro331/go-mvn-version) ──────────────────────────────────────

func compareMaven(a, b string) (int, bool) {
	va, err := mvn.NewVersion(a)
	if err != nil {
		return 0, false
	}
	vb, err := mvn.NewVersion(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// ── Generic fallback ────────────────────────────────────────────────────────
// Hand-rolled normaliser: split on . / - / +, numeric segments compared as
// ints, alpha lexically, numeric < alpha for pre-release ordering, and a
// number with a suffix ("11n") by its number first.

func compareGeneric(a, b string) (int, bool) {
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
		cmp := compareSegment(pa, pb)
		if cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func splitVersion(v string) []string {
	// Split on . - + _
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '+' || r == '_'
	})
}

func compareSegment(a, b string) int {
	aNum, aIsNum := parseNumeric(a)
	bNum, bIsNum := parseNumeric(b)

	// A segment such as "11n" (util-linux 2.11n, OpenSSL 1.0.2k) is a number
	// with a suffix. Ranking it as text put every number below it, so 2.37.2
	// sorted before 2.11n. Compare the numbers first, as dpkg and rpm do.
	if !(aIsNum && bIsNum) {
		la, ra := leadingDigits(a)
		lb, rb := leadingDigits(b)
		if la != "" && lb != "" {
			if c := compareDigits(la, lb); c != 0 {
				return c
			}
			switch {
			case ra == rb:
				return 0
			case ra == "":
				return -suffixOrder(rb)
			case rb == "":
				return suffixOrder(ra)
			}
			if oa, ob := suffixOrder(ra), suffixOrder(rb); oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			return compareSuffix(ra, rb)
		}
	}

	if aIsNum && bIsNum {
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
		return 0
	}
	if aIsNum && !bIsNum {
		// numeric < alpha (pre-release ordering)
		if b == "" {
			return 1 // 1.0 > 1.0-
		}
		return -1
	}
	if !aIsNum && bIsNum {
		if a == "" {
			return -1 // 1.0- < 1.0
		}
		return 1
	}
	return strings.Compare(a, b)
}

func leadingDigits(s string) (digits, rest string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// compareDigits orders two digit strings by value without overflowing.
func compareDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// suffixOrder says where a number with this suffix sorts against the bare
// number: before it for a pre-release ("1rc1", "0b2"), after it for a letter
// release ("2k" follows "2").
func suffixOrder(suffix string) int {
	s := strings.ToLower(suffix)
	for _, p := range []string{"alpha", "beta", "pre", "rc", "dev", "preview", "snapshot"} {
		if strings.HasPrefix(s, p) {
			return -1
		}
	}
	if len(s) > 1 && (s[0] == 'a' || s[0] == 'b' || s[0] == 'c') && s[1] >= '0' && s[1] <= '9' {
		return -1
	}
	return 1
}

// compareSuffix orders two suffixes of the same kind: the letters as text,
// then what follows them ("rc2" before "rc10").
func compareSuffix(a, b string) int {
	i, j := 0, 0
	for i < len(a) && (a[i] < '0' || a[i] > '9') {
		i++
	}
	for j < len(b) && (b[j] < '0' || b[j] > '9') {
		j++
	}
	if c := strings.Compare(a[:i], b[:j]); c != 0 {
		return c
	}
	return compareSegment(a[i:], b[j:])
}

func parseNumeric(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
