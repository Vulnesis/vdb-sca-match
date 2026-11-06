package version

import (
	"regexp"
	"strconv"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	mvn "github.com/masahiro331/go-mvn-version"
)

// ── PEP 440 (PyPI) ──────────────────────────────────────────────────────────

type pep440Algo struct{}

var (
	pep440Dev = regexp.MustCompile(`\.dev[0-9]*`)
	pep440Pre = regexp.MustCompile(`[0-9](a|b|rc)[0-9]*`)
)

func (pep440Algo) compare(a, b string) (int, bool) { return comparePEP440(a, b) }

func (pep440Algo) classify(v string) (bool, bool, []string) {
	p, err := pep440.Parse(strings.TrimSpace(v))
	if err != nil {
		return unparseable()
	}
	var reasons []string
	norm := p.String()
	if pep440Pre.MatchString(pep440Dev.ReplaceAllString(norm, "")) {
		reasons = append(reasons, ReasonPrerelease)
	}
	if pep440Dev.MatchString(norm) {
		reasons = append(reasons, ReasonDev)
	}
	if p.Local() != "" {
		reasons = append(reasons, ReasonLocalVersion)
	}
	return verdict(reasons...)
}

// ── Maven ComparableVersion and Gradle ──────────────────────────────────────

var (
	mvnToken      = regexp.MustCompile(`[a-z]+|[0-9]+`)
	mvnTimestamp  = regexp.MustCompile(`(^|[.-])[0-9]{8}\.[0-9]{6}-[0-9]+$`)
	mvnStartsWith = regexp.MustCompile(`^[0-9]`)
)

// mavenStability applies the stable-release rule shared by Maven, Gradle, Ivy
// and Coursier. Unknown qualifiers (dev, ea, preview, nightly, canary) sort ABOVE
// the release in Maven, which is why the ordering alone cannot be trusted to
// keep them out.
func mavenStability(v string) (bool, bool, []string) {
	lv := strings.ToLower(strings.TrimSpace(v))
	if !mvnStartsWith.MatchString(lv) {
		return unparseable()
	}
	var reasons []string
	if mvnTimestamp.MatchString(lv) {
		reasons = append(reasons, ReasonSnapshot)
	}
	toks := mvnToken.FindAllString(lv, -1)
	for i, t := range toks {
		followedByDigit := i+1 < len(toks) && toks[i+1][0] >= '0' && toks[i+1][0] <= '9'
		switch t {
		case "snapshot":
			reasons = append(reasons, ReasonSnapshot)
		case "alpha", "beta", "rc", "cr", "pre", "preview", "ea", "canary":
			reasons = append(reasons, ReasonPrerelease)
		case "milestone":
			reasons = append(reasons, ReasonMilestone)
		case "dev":
			reasons = append(reasons, ReasonDev)
		case "nightly":
			reasons = append(reasons, ReasonNightly)
		case "a", "b":
			// Shorthand qualifiers only count directly before a digit: 1.0-b2.
			if followedByDigit && i > 0 {
				reasons = append(reasons, ReasonPrerelease)
			}
		case "m":
			if followedByDigit && i > 0 {
				reasons = append(reasons, ReasonMilestone)
			}
		}
	}
	if strings.Contains(lv, "+") {
		reasons = append(reasons, ReasonBuildMetadata)
	}
	return verdict(dedupe(reasons)...)
}

type mavenAlgo struct{}

func (mavenAlgo) compare(a, b string) (int, bool) {
	if !mvnStartsWith.MatchString(strings.TrimSpace(a)) || !mvnStartsWith.MatchString(strings.TrimSpace(b)) {
		return 0, false
	}
	va, err := mvn.NewVersion(strings.TrimSpace(a))
	if err != nil {
		return 0, false
	}
	vb, err := mvn.NewVersion(strings.TrimSpace(b))
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

func (mavenAlgo) classify(v string) (bool, bool, []string) { return mavenStability(v) }

// gradleAlgo ports Gradle's StaticVersionComparator: parts split on . - _ + and
// at digit/letter boundaries; a number beats a string; dev < rc < snapshot <
// final < ga < release < sp; and a trailing string part sorts BELOW a bare
// version (1.0-sp1 < 1.0), the opposite of Maven.
type gradleAlgo struct{}

var gradleSpecial = map[string]int{"dev": -1, "rc": 1, "snapshot": 2, "final": 3, "ga": 4, "release": 5, "sp": 6}

func gradleParts(v string) []string {
	var parts []string
	var cur []byte
	kind := byte(0) // 'd' digit, 'a' other
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = cur[:0]
		}
		kind = 0
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch c {
		case '.', '-', '_', '+':
			flush()
			continue
		}
		k := byte('a')
		if c >= '0' && c <= '9' {
			k = 'd'
		}
		if kind != 0 && k != kind {
			flush()
		}
		kind = k
		cur = append(cur, c)
	}
	flush()
	return parts
}

func (gradleAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !mvnStartsWith.MatchString(a) || !mvnStartsWith.MatchString(b) {
		return 0, false
	}
	if a == b {
		return 0, true
	}
	p1, p2 := gradleParts(a), gradleParts(b)
	num := func(s string) (int64, bool) {
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	i := 0
	for ; i < len(p1) && i < len(p2); i++ {
		x, y := p1[i], p2[i]
		xn, xok := num(x)
		yn, yok := num(y)
		switch {
		case xok && !yok:
			return 1, true
		case !xok && yok:
			return -1, true
		case xok && yok:
			if xn != yn {
				if xn < yn {
					return -1, true
				}
				return 1, true
			}
			continue
		}
		if x == y {
			continue
		}
		sx, hx := gradleSpecial[strings.ToLower(x)]
		sy, hy := gradleSpecial[strings.ToLower(y)]
		if hx {
			return clamp(sx - sy*boolInt(hy)), true
		}
		if hy {
			return clamp(-sy), true
		}
		if c := strings.Compare(x, y); c != 0 {
			return c, true
		}
	}
	if i < len(p1) {
		if _, ok := num(p1[i]); ok {
			return 1, true
		}
		return -1, true
	}
	if i < len(p2) {
		if _, ok := num(p2[i]); ok {
			return -1, true
		}
		return 1, true
	}
	return 0, true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func clamp(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func (gradleAlgo) classify(v string) (bool, bool, []string) { return mavenStability(v) }

// ── RubyGems (Gem::Version) ─────────────────────────────────────────────────

type rubygemsAlgo struct{}

var (
	gemVersionRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	gemSegmentRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)
	gemLetterRe  = regexp.MustCompile(`[a-zA-Z]`)
)

// gemSegments returns the canonical segments of Gem::Version: numeric and string
// runs, with trailing zeros dropped from the leading numeric run and from the
// rest separately.
func gemSegments(v string) ([]string, bool) {
	v = strings.TrimSpace(v)
	if !gemVersionRe.MatchString(v) {
		return nil, false
	}
	v = strings.ReplaceAll(v, "-", ".pre.")
	segs := gemSegmentRe.FindAllString(v, -1)
	split := len(segs)
	for i, s := range segs {
		if s[0] < '0' || s[0] > '9' {
			split = i
			break
		}
	}
	isZero := func(s string) bool { return s != "" && strings.Trim(s, "0") == "" && s[0] == '0' }
	trim := func(in []string) []string {
		end := len(in)
		for end > 0 && isZero(in[end-1]) {
			end--
		}
		return in[:end]
	}
	out := append([]string{}, trim(segs[:split])...)
	return append(out, trim(segs[split:])...), true
}

func (rubygemsAlgo) compare(a, b string) (int, bool) {
	sa, ok := gemSegments(a)
	if !ok {
		return 0, false
	}
	sb, ok := gemSegments(b)
	if !ok {
		return 0, false
	}
	n := len(sa)
	if len(sb) > n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		if x == y {
			continue
		}
		xs := x[0] < '0' || x[0] > '9'
		ys := y[0] < '0' || y[0] > '9'
		switch {
		case xs && !ys:
			return -1, true
		case !xs && ys:
			return 1, true
		case !xs && !ys:
			if c := cmpDigits(trimZeros(x), trimZeros(y)); c != 0 {
				return c, true
			}
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c, true
			}
		}
	}
	return 0, true
}

// classify: any ASCII letter (including post, final, a platform word) or a
// hyphen (rewritten to .pre.) makes a gem version a prerelease.
func (rubygemsAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if !gemVersionRe.MatchString(v) {
		return unparseable()
	}
	if gemLetterRe.MatchString(v) || strings.Contains(v, "-") {
		if specific := channelReasons(v); len(specific) > 0 {
			return verdict(specific...)
		}
		return verdict(ReasonPrerelease)
	}
	return verdict()
}

// ── conda (VersionOrder) ────────────────────────────────────────────────────

type condaAlgo struct{}

type condaVer struct {
	epoch int
	comps [][]condaAtom
	local [][]condaAtom
}

// condaAtom is an int or a lowercase string. Strings sort below ints; "dev" is
// the lowest string and "post" the highest.
type condaAtom struct {
	n     int
	s     string
	isStr bool
}

var condaValid = regexp.MustCompile(`^[*.+!_0-9a-z]+$`)
var condaRun = regexp.MustCompile(`[0-9]+|[^0-9]+`)

func condaComponents(s string) [][]condaAtom {
	var out [][]condaAtom
	for _, piece := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '_' }) {
		var atoms []condaAtom
		for _, run := range condaRun.FindAllString(piece, -1) {
			if run[0] >= '0' && run[0] <= '9' {
				n, _ := strconv.Atoi(run)
				atoms = append(atoms, condaAtom{n: n})
			} else {
				atoms = append(atoms, condaAtom{s: run, isStr: true})
			}
		}
		if len(atoms) > 0 && atoms[0].isStr {
			atoms = append([]condaAtom{{n: 0}}, atoms...)
		}
		if len(atoms) > 0 {
			out = append(out, atoms)
		}
	}
	return out
}

func condaParse(v string) (condaVer, bool) {
	var out condaVer
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || strings.Contains(v, "..") {
		return out, false
	}
	if !condaValid.MatchString(v) {
		if strings.Contains(v, "-") && !strings.Contains(v, "_") {
			v = strings.ReplaceAll(v, "-", "_")
		}
		if !condaValid.MatchString(v) {
			return out, false
		}
	}
	if i := strings.IndexByte(v, '!'); i >= 0 {
		e, err := strconv.Atoi(v[:i])
		if err != nil || strings.Contains(v[i+1:], "!") {
			return out, false
		}
		out.epoch, v = e, v[i+1:]
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		out.local = condaComponents(v[i+1:])
		v = v[:i]
	}
	// A trailing underscore (1.0.1_) is a string atom "_" on the last component:
	// above dev, below any letter. It lets openssl-style letter versions sort.
	trailing := strings.HasSuffix(v, "_")
	out.comps = condaComponents(strings.TrimRight(v, "_"))
	if trailing && len(out.comps) > 0 {
		last := len(out.comps) - 1
		out.comps[last] = append(out.comps[last], condaAtom{s: "_", isStr: true})
	}
	return out, len(out.comps) > 0
}

func condaCmpAtom(a, b condaAtom) int {
	switch {
	case a.isStr && a.s == "post" && (!b.isStr || b.s != "post"):
		return 1 // post outranks everything, ints included
	case b.isStr && b.s == "post" && (!a.isStr || a.s != "post"):
		return -1
	case a.isStr && !b.isStr:
		return -1
	case !a.isStr && b.isStr:
		return 1
	case !a.isStr:
		return cmpInt(a.n, b.n)
	}
	switch {
	case a.s == b.s:
		return 0
	case a.s == "dev":
		return -1
	case b.s == "dev":
		return 1
	case a.s == "post":
		return 1
	case b.s == "post":
		return -1
	}
	return strings.Compare(a.s, b.s)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func condaCmpComps(a, b [][]condaAtom) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	zero := []condaAtom{{n: 0}}
	for i := 0; i < n; i++ {
		x, y := zero, zero
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		m := len(x)
		if len(y) > m {
			m = len(y)
		}
		for j := 0; j < m; j++ {
			p, q := condaAtom{n: 0}, condaAtom{n: 0}
			if j < len(x) {
				p = x[j]
			}
			if j < len(y) {
				q = y[j]
			}
			if c := condaCmpAtom(p, q); c != 0 {
				return c
			}
		}
	}
	return 0
}

func (condaAlgo) compare(a, b string) (int, bool) {
	va, ok := condaParse(a)
	if !ok {
		return 0, false
	}
	vb, ok := condaParse(b)
	if !ok {
		return 0, false
	}
	if va.epoch != vb.epoch {
		return cmpInt(va.epoch, vb.epoch), true
	}
	if c := condaCmpComps(va.comps, vb.comps); c != 0 {
		return c, true
	}
	return condaCmpComps(va.local, vb.local), true
}

func (condaAlgo) classify(v string) (bool, bool, []string) {
	p, ok := condaParse(v)
	if !ok {
		return unparseable()
	}
	lv := strings.ToLower(strings.TrimSpace(v))
	var reasons []string
	switch {
	case strings.Contains(lv, "dev"):
		reasons = append(reasons, ReasonDev)
	case condaHasPre(p):
		reasons = append(reasons, ReasonPrerelease)
	}
	if len(p.local) > 0 {
		reasons = append(reasons, ReasonLocalVersion)
	}
	return verdict(reasons...)
}

func condaHasPre(p condaVer) bool {
	for _, comp := range p.comps {
		for _, a := range comp {
			if !a.isStr {
				continue
			}
			switch a.s {
			case "a", "alpha", "b", "beta", "c", "rc", "pre", "preview":
				return true
			}
		}
	}
	return false
}
