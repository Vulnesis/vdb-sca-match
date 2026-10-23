package version

import (
	"regexp"
	"strings"
)

// semverOpts captures where the SemVer-shaped registries differ. The research
// behind each choice is in schemes.json (ordering, buildMetadata, prerelease).
type semverOpts struct {
	// vPrefix: "optional" (npm, swift, helm), "required" (go), "forbidden" (cargo, hex, pub).
	// Only a lowercase v is ever accepted.
	vPrefix string
	// minParts/maxParts bound the numeric core (3/3 strict; nuget 1/4; lenient 1/4).
	minParts, maxParts int
	// buildCompared orders build metadata after the release (cargo, pub, julia).
	buildCompared bool
	// foldCase lowercases pre-release identifiers before comparing (nuget).
	foldCase bool
	// leadingZeros accepts 01.0.0 in the numeric core (pub, swift, helm, nuget).
	leadingZeros bool
	// noPreLeadingZeros still rejects a numeric pre-release id like -01 (nuget, helm).
	noPreLeadingZeros bool
	// maxNum rejects a numeric core part above this value (cargo u64, nuget int32).
	maxNum string
	// lax accepts empty pre-release/build parts and empty identifiers (swift,
	// julia, terraform), which their reference parsers do. laxBuild is the
	// subset that also accepts an empty '+' (terraform rejects it).
	lax, laxBuild bool
	// upperV also accepts a capital V (julia).
	upperV bool
	// emptyPartQuirk reproduces hashicorp/go-version: a missing pre-release
	// identifier sorts above a non-numeric one, so 1.0.0-alpha.beta < 1.0.0-alpha.
	emptyPartQuirk bool
	// emptyBuildHighest sorts a bare '+' above every concrete build (julia).
	emptyBuildHighest bool
	// noPad makes a shorter numeric core sort below a longer one that extends
	// it (1 < 1.0 < 1.0.0), instead of padding with zeros (vcpkg).
	noPad bool
	// bareLetterPre accepts a pre-release glued to the core without a hyphen:
	// 1.0.0beta1 (terraform, julia).
	bareLetterPre bool
	// goPseudo recognises Go pseudo-versions and the +incompatible suffix.
	goPseudo bool
	// firstPreAsText compares a numeric first pre-release id as text (rebar3).
	firstPreAsText bool
	// buildStable keeps a version with a (non-channel) build suffix stable. Build
	// metadata never decides stability by itself: Dart's 0.1.2+1, Go's
	// +incompatible and Cargo's +abc are all ordinary releases. Only a channel
	// word inside it (+nightly, +snapshot, +dev) makes the version unstable.
	buildStable func(build string) bool
}

type semverAlgo struct{ o semverOpts }

type semverVer struct {
	nums  []string // digit strings without leading zeros
	pre   []string
	build string
	hasB  bool
	hasP  bool
	raw   string
}

var (
	preIDRe   = regexp.MustCompile(`^[0-9A-Za-z~-]*$`)
	digitsRe  = regexp.MustCompile(`^[0-9]+$`)
	goPseudoR = regexp.MustCompile(`^v[0-9]+\.(0\.0-|[0-9]+\.[0-9]+-([^+]*\.)?0\.)[0-9]{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

func (s semverAlgo) parse(v string) (semverVer, bool) {
	var out semverVer
	out.raw = strings.TrimSpace(v)
	v = out.raw
	if v == "" {
		return out, false
	}
	hasV := false
	if v[0] == 'v' || (s.o.upperV && v[0] == 'V') {
		hasV = true
		v = v[1:]
	}
	switch s.o.vPrefix {
	case "required":
		if !hasV {
			return out, false
		}
	case "forbidden":
		if hasV {
			return out, false
		}
	}
	if v == "" {
		return out, false
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		out.build, out.hasB = v[i+1:], true
		if out.build == "" && !s.o.laxBuild {
			return out, false
		}
		if out.build != "" {
			for _, id := range strings.Split(out.build, ".") {
				if (id == "" && !s.o.laxBuild) || !preIDRe.MatchString(id) {
					return out, false
				}
			}
		}
		v = v[:i]
	}
	core, pre := v, ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		core, pre, out.hasP = v[:i], v[i+1:], true
		if pre == "" && !s.o.lax {
			return out, false
		}
	} else if s.o.bareLetterPre {
		for i := 0; i < len(v); i++ {
			if isAlpha(v[i]) {
				core, pre, out.hasP = v[:i], v[i:], true
				break
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) < s.o.minParts || len(parts) > s.o.maxParts {
		return out, false
	}
	for _, p := range parts {
		if !digitsRe.MatchString(p) {
			return out, false
		}
		if !s.o.leadingZeros && len(p) > 1 && p[0] == '0' {
			return out, false
		}
		p = trimZeros(p)
		if s.o.maxNum != "" && cmpDigits(p, s.o.maxNum) > 0 {
			return out, false
		}
		out.nums = append(out.nums, p)
	}
	if pre != "" || (out.hasP && s.o.lax) {
		for _, id := range strings.Split(pre, ".") {
			if (id == "" && !s.o.lax) || !preIDRe.MatchString(id) {
				return out, false
			}
			if (!s.o.leadingZeros || s.o.noPreLeadingZeros) && len(id) > 1 && id[0] == '0' && digitsRe.MatchString(id) {
				return out, false
			}
			if s.o.foldCase {
				id = strings.ToLower(id)
			}
			out.pre = append(out.pre, id)
		}
	}
	return out, true
}

func trimZeros(d string) string {
	d = strings.TrimLeft(d, "0")
	if d == "" {
		return "0"
	}
	return d
}

// cmpDigits orders two digit strings without leading zeros.
func cmpDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func (s semverAlgo) cmpPre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if x != y && (x == "" || y == "") {
			if x == "" {
				return -1
			}
			return 1
		}
		xn, yn := digitsRe.MatchString(x), digitsRe.MatchString(y)
		if i == 0 && s.o.firstPreAsText {
			xn, yn = false, false
		}
		switch {
		case xn && yn:
			if c := cmpDigits(trimZeros(x), trimZeros(y)); c != 0 {
				return c
			}
		case xn:
			return -1
		case yn:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	if s.o.emptyPartQuirk && len(a) != len(b) {
		// go-version compares the missing identifier as an empty string: it sorts
		// below a numeric identifier and above a non-numeric one.
		longer, sign := b, 1
		if len(a) > len(b) {
			longer, sign = a, -1
		}
		if digitsRe.MatchString(longer[min(len(a), len(b))]) {
			return -sign
		}
		return sign
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func (s semverAlgo) cmpVer(a, b semverVer) int {
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		if s.o.noPad && (i >= len(a.nums) || i >= len(b.nums)) {
			return cmpInt(len(a.nums), len(b.nums))
		}
		x, y := "0", "0"
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if c := cmpDigits(x, y); c != 0 {
			return c
		}
	}
	if c := s.cmpPre(a.pre, b.pre); c != 0 {
		return c
	}
	if s.o.buildCompared {
		switch {
		case !a.hasB && !b.hasB:
			return 0
		case !a.hasB:
			return -1
		case !b.hasB:
			return 1
		}
		if s.o.emptyBuildHighest && (a.build == "") != (b.build == "") {
			if a.build == "" {
				return 1
			}
			return -1
		}
		return s.cmpBuild(strings.Split(a.build, "."), strings.Split(b.build, "."))
	}
	return 0
}

func (s semverAlgo) compare(a, b string) (int, bool) {
	va, ok := s.parse(a)
	if !ok {
		return 0, false
	}
	vb, ok := s.parse(b)
	if !ok {
		return 0, false
	}
	return s.cmpVer(va, vb), true
}

func (s semverAlgo) classify(v string) (bool, bool, []string) {
	p, ok := s.parse(v)
	if !ok {
		return unparseable()
	}
	var reasons []string
	if s.o.goPseudo && goPseudoR.MatchString(p.raw) {
		reasons = append(reasons, ReasonPseudoVersion, ReasonPrerelease)
	} else if p.hasP {
		reasons = append(reasons, ReasonPrerelease)
		reasons = append(reasons, channelReasons(strings.Join(p.pre, "."))...)
	}
	if p.hasB && !(s.o.buildStable != nil && s.o.buildStable(p.build)) {
		if ch := channelReasons(p.build); len(ch) > 0 {
			reasons = append(reasons, ch...)
		}
	}
	return verdict(dedupe(reasons)...)
}

// goBuildStable documents +incompatible: it marks a v2+ module that predates Go
// modules, and says nothing about the release's maturity.
func goBuildStable(build string) bool { return build == "incompatible" }

// cmpBuild orders two non-empty build identifier lists the way pre-release
// identifiers are ordered, except that a list never loses to a shorter prefix of
// itself being "absent": equal prefixes make the shorter one lower.
func (s semverAlgo) cmpBuild(a, b []string) int {
	return semverAlgo{semverOpts{}}.cmpPre(a, b)
}
