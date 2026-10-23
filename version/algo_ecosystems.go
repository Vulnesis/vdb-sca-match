package version

import (
	"regexp"
	"strconv"
	"strings"
)

func init() {
	registry["hackage"] = dottedAlgo{kind: "hackage"}
	registry["cran"] = dottedAlgo{kind: "cran"}
	registry["bioconductor"] = dottedAlgo{kind: "bioconductor"}
	registry["cpan"] = cpanAlgo{}
	registry["composer"] = composerAlgo{}
	registry["cocoapods"] = cocoapodsAlgo{}
	registry["conan"] = conanAlgo{}
	registry["luarocks"] = luarocksAlgo{}
	registry["clojars"] = clojarsAlgo{}
	registry["zerover"] = zeroverAlgo{semverAlgo{semverOpts{vPrefix: "optional", minParts: 3, maxParts: 3}}}
	registry["opam"] = opamAlgo{}
	registry["homebrew"] = homebrewAlgo{}

	// vcpkg declares its version scheme in the manifest, so the string alone
	// does not say which applies; "vcpkg" is the relaxed `version` field.
	registry["vcpkg"] = semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 1, maxParts: 16, noPad: true}}
	registry["vcpkg:version"] = registry["vcpkg"]
	registry["vcpkg:version-semver"] = semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3}}
	registry["vcpkg:version-date"] = vcpkgDateAlgo{}
	registry["vcpkg:version-string"] = vcpkgStringAlgo{}
	registry["vcpkg:version+port-version"] = vcpkgPortAlgo{}
}

// cmpIntLists orders integer lists element by element; when one is a prefix of
// the other the shorter is lower (1 < 1.0 < 1.0.0), as in Haskell's PVP and R.
func cmpIntLists(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpDigits(trimZeros(a[i]), trimZeros(b[i])); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

// ── Hackage (PVP), CRAN and Bioconductor ────────────────────────────────────

type dottedAlgo struct{ kind string }

var (
	hackageRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	rRe       = regexp.MustCompile(`^[0-9]+([.-][0-9]+)+$`)
)

func (d dottedAlgo) parts(v string) ([]string, bool) {
	re := rRe
	if d.kind == "hackage" {
		re = hackageRe
	}
	if !re.MatchString(v) {
		return nil, false
	}
	return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' }), true
}

func (d dottedAlgo) compare(a, b string) (int, bool) {
	pa, ok := d.parts(a)
	if !ok {
		return 0, false
	}
	pb, ok := d.parts(b)
	if !ok {
		return 0, false
	}
	return cmpIntLists(pa, pb), true
}

func (d dottedAlgo) classify(v string) (bool, bool, []string) {
	p, ok := d.parts(v)
	if !ok {
		return unparseable()
	}
	switch d.kind {
	case "cran":
		// Convention: a fourth component of 9000 or more marks a development
		// version (1.2.3.9000) between two releases.
		for i := 3; i < len(p); i++ {
			if n, err := strconv.Atoi(p[i]); err == nil && n >= 9000 {
				return verdict(ReasonDev)
			}
		}
	case "bioconductor":
		// An odd minor is the development branch of the next release (0.99.x is
		// a package awaiting its first release).
		if n, err := strconv.Atoi(p[1]); err == nil && n%2 == 1 {
			return verdict(ReasonDev)
		}
	}
	return verdict()
}

// ── CPAN (version.pm) ───────────────────────────────────────────────────────

type cpanAlgo struct{}

var cpanRe = regexp.MustCompile(`^v?[0-9]+(\.[0-9_]*)*$`)

// cpanParts follows version.pm: a dotted version (leading v, or two or more
// dots) is a list of integers; a decimal one reads its fraction in groups of
// three digits, so 1.2 is v1.200 and 1.10 sorts below 1.9.
func cpanParts(v string) (parts []int, dev, ok bool) {
	if !cpanRe.MatchString(v) || strings.HasPrefix(v, "_") || strings.HasSuffix(v, "_") {
		return nil, false, false
	}
	if strings.Count(v, "_") > 1 || strings.Contains(v, "._") || strings.Contains(v, "_.") {
		return nil, false, false
	}
	dev = strings.Contains(v, "_")
	clean := strings.ReplaceAll(v, "_", "")
	dotted := strings.HasPrefix(clean, "v") || strings.Count(clean, ".") >= 2
	clean = strings.TrimPrefix(clean, "v")
	if dotted {
		if strings.HasSuffix(clean, ".") || strings.Contains(clean, "..") {
			return nil, false, false
		}
		for _, s := range strings.Split(clean, ".") {
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil, false, false
			}
			parts = append(parts, n)
		}
		return parts, dev, true
	}
	whole, frac, _ := strings.Cut(clean, ".")
	n, err := strconv.Atoi(whole)
	if err != nil {
		return nil, false, false
	}
	parts = append(parts, n)
	for len(frac)%3 != 0 {
		frac += "0"
	}
	for i := 0; i < len(frac); i += 3 {
		g, _ := strconv.Atoi(frac[i : i+3])
		parts = append(parts, g)
	}
	return parts, dev, true
}

func (cpanAlgo) compare(a, b string) (int, bool) {
	pa, _, ok := cpanParts(a)
	if !ok {
		return 0, false
	}
	pb, _, ok := cpanParts(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return cmpInt(x, y), true
		}
	}
	return 0, true
}

// classify: an underscore marks an alpha (developer) release on CPAN.
func (cpanAlgo) classify(v string) (bool, bool, []string) {
	_, dev, ok := cpanParts(v)
	if !ok {
		return unparseable()
	}
	if dev {
		return verdict(ReasonDev)
	}
	return verdict()
}

// ── Composer ────────────────────────────────────────────────────────────────

type composerAlgo struct{}

var (
	composerRe = regexp.MustCompile(`(?i)^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:\.([0-9]+))?(?:[._-]?(dev|alpha|a|beta|b|rc|patch|pl|p|stable)(?:[._-]?([0-9]+(?:\.[0-9]+)*))?)?(?:\+[0-9A-Za-z.-]+)?$`)
	// composerBranch matches dev-<branch>, 1.x-dev and 1.0.x-dev.
	composerBranch = regexp.MustCompile(`(?i)^(dev-.+|[0-9]+(\.[0-9]+)*\.x-dev|master|trunk|default)$`)
)

type composerVer struct {
	nums   [4]string
	rank   int // dev 0, alpha 1, beta 2, RC 3, stable 4, patch 5; branch -1
	modNum string
	branch string
}

func composerParse(v string) (composerVer, bool) {
	var out composerVer
	v = strings.TrimSpace(v)
	if composerBranch.MatchString(v) {
		out.rank, out.branch = -1, strings.ToLower(v)
		return out, true
	}
	m := composerRe.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	for i := 0; i < 4; i++ {
		out.nums[i] = "0"
		if m[i+1] != "" {
			out.nums[i] = trimZeros(m[i+1])
		}
	}
	out.rank = 4
	switch strings.ToLower(m[5]) {
	case "dev":
		out.rank = 0
	case "alpha", "a":
		out.rank = 1
	case "beta", "b":
		out.rank = 2
	case "rc":
		out.rank = 3
	case "patch", "pl", "p":
		out.rank = 5
	}
	out.modNum = m[6]
	return out, true
}

func (composerAlgo) compare(a, b string) (int, bool) {
	va, ok := composerParse(a)
	if !ok {
		return 0, false
	}
	vb, ok := composerParse(b)
	if !ok {
		return 0, false
	}
	if va.branch != "" || vb.branch != "" {
		switch {
		case va.branch != "" && vb.branch != "":
			return clamp(strings.Compare(va.branch, vb.branch)), true
		case va.branch != "":
			return -1, true
		}
		return 1, true
	}
	for i := 0; i < 4; i++ {
		if c := cmpDigits(va.nums[i], vb.nums[i]); c != 0 {
			return c, true
		}
	}
	if va.rank != vb.rank {
		return cmpInt(va.rank, vb.rank), true
	}
	return cmpIntLists(strings.Split(va.modNum, "."), strings.Split(vb.modNum, ".")), true
}

func (composerAlgo) classify(v string) (bool, bool, []string) {
	p, ok := composerParse(v)
	if !ok {
		return unparseable()
	}
	switch {
	case p.branch != "":
		return verdict(ReasonBranchRef, ReasonDev)
	case p.rank == 0:
		return verdict(ReasonDev)
	case p.rank >= 1 && p.rank <= 3:
		return verdict(ReasonPrerelease)
	}
	return verdict()
}

// ── CocoaPods (Pod::Version, built on Gem::Version) ─────────────────────────

type cocoapodsAlgo struct{}

// cocoapodsMain turns 1.0.0-beta.2+build into the Gem::Version string
// 1.0.0.beta.2: a hyphen becomes a dot, and build metadata is dropped.
func cocoapodsMain(v string) (main string, pre bool, ok bool) {
	if v == "" || strings.HasSuffix(v, "+") {
		return "", false, false
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if strings.HasSuffix(v, "-") {
		return strings.TrimSuffix(v, "-"), true, gemVersionRe.MatchString(strings.TrimSuffix(v, "-"))
	}
	pre = strings.Contains(v, "-")
	v = strings.Replace(v, "-", ".", 1)
	if !gemVersionRe.MatchString(v) || strings.Contains(v, "_") {
		return "", false, false
	}
	return v, pre, true
}

func (cocoapodsAlgo) compare(a, b string) (int, bool) {
	ma, _, ok := cocoapodsMain(a)
	if !ok {
		return 0, false
	}
	mb, _, ok := cocoapodsMain(b)
	if !ok {
		return 0, false
	}
	return rubygemsAlgo{}.compare(ma, mb)
}

func (cocoapodsAlgo) classify(v string) (bool, bool, []string) {
	m, hyphen, ok := cocoapodsMain(v)
	if !ok {
		return unparseable()
	}
	if hyphen || gemLetterRe.MatchString(m) {
		return verdict(append([]string{ReasonPrerelease}, channelReasons(m)...)...)
	}
	return verdict()
}

// ── Conan ───────────────────────────────────────────────────────────────────

type conanAlgo struct{}

var conanHasDigit = regexp.MustCompile(`[0-9]`)

type conanItem struct {
	n     string
	s     string
	isNum bool
}

func conanItems(s string) []conanItem {
	var out []conanItem
	for _, p := range strings.Split(s, ".") {
		if digitsRe.MatchString(p) {
			out = append(out, conanItem{n: trimZeros(p), isNum: true})
		} else {
			out = append(out, conanItem{s: p})
		}
	}
	return out
}

func conanCmpItems(a, b []conanItem) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := conanItem{n: "0", isNum: true}, conanItem{n: "0", isNum: true}
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x.isNum && y.isNum:
			if c := cmpDigits(x.n, y.n); c != 0 {
				return c
			}
		case x.isNum:
			return -1
		case y.isNum:
			return 1
		default:
			if c := strings.Compare(x.s, y.s); c != 0 {
				return c
			}
		}
	}
	return 0
}

// conanSplit separates core, pre-release and build; Conan accepts any string
// with a digit, so the only way to be unparseable is to have none.
func conanSplit(v string) (core, pre string, hasPre, ok bool) {
	if v == "" || !conanHasDigit.MatchString(v) {
		return "", "", false, false
	}
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:], true, true
	}
	return v, "", false, true
}

func (conanAlgo) compare(a, b string) (int, bool) {
	ca, pa, hpa, ok := conanSplit(a)
	if !ok {
		return 0, false
	}
	cb, pb, hpb, ok := conanSplit(b)
	if !ok {
		return 0, false
	}
	if c := conanCmpItems(conanItems(ca), conanItems(cb)); c != 0 {
		return c, true
	}
	switch {
	case !hpa && !hpb:
		return 0, true
	case !hpa:
		return 1, true
	case !hpb:
		return -1, true
	}
	return conanCmpItems(conanItems(pa), conanItems(pb)), true
}

func (conanAlgo) classify(v string) (bool, bool, []string) {
	_, pre, hasPre, ok := conanSplit(v)
	if !ok {
		return unparseable()
	}
	if hasPre {
		return verdict(append([]string{ReasonPrerelease}, channelReasons(pre)...)...)
	}
	return verdict()
}

// ── LuaRocks ────────────────────────────────────────────────────────────────

type luarocksAlgo struct{}

var (
	luarocksRev  = regexp.MustCompile(`^(.*)-([0-9]+)$`)
	luarocksTok  = regexp.MustCompile(`[0-9]+|[a-z]+`)
	luarocksWord = map[string]int{"dev": 120000000, "scm": 110000000, "cvs": 100000000, "rc": -1000, "pre": -10000, "beta": -100000, "alpha": -1000000}
	luarocksRaw  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)

	luarocksBranch = regexp.MustCompile(`^(scm|cvs|dev)(-|$)`)
)

func luarocksParse(v string) (toks []int, rev int, ok bool) {
	v = strings.ToLower(v)
	// A rock version starts with a number, or is one of the branch markers
	// scm/cvs/dev; a leading v is not accepted.
	if !luarocksRaw.MatchString(v) || !(isDigit(v[0]) || luarocksBranch.MatchString(v)) {
		return nil, 0, false
	}
	if m := luarocksRev.FindStringSubmatch(v); m != nil {
		v = m[1]
		rev, _ = strconv.Atoi(m[2])
	}
	for _, t := range luarocksTok.FindAllString(v, -1) {
		if n, err := strconv.Atoi(t); err == nil {
			toks = append(toks, n)
		} else if w, known := luarocksWord[t]; known {
			toks = append(toks, w)
		} else {
			// An unknown word sorts like a small positive build tag.
			toks = append(toks, 1)
		}
	}
	return toks, rev, len(toks) > 0
}

func (luarocksAlgo) compare(a, b string) (int, bool) {
	ta, ra, ok := luarocksParse(a)
	if !ok {
		return 0, false
	}
	tb, rb, ok := luarocksParse(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < len(ta) || i < len(tb); i++ {
		x, y := 0, 0
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if x != y {
			return cmpInt(x, y), true
		}
	}
	return cmpInt(ra, rb), true
}

var luarocksPre = regexp.MustCompile(`(^|[^a-z])(alpha|beta|pre|rc)`)

func (luarocksAlgo) classify(v string) (bool, bool, []string) {
	if _, _, ok := luarocksParse(v); !ok {
		return unparseable()
	}
	lv := strings.ToLower(v)
	name := luarocksRev.ReplaceAllString(lv, "$1")
	var reasons []string
	if name == "scm" || name == "dev" || name == "cvs" {
		return verdict(ReasonDev, ReasonBranchRef)
	}
	if strings.Contains(name, "dev") || strings.Contains(name, "scm") || strings.Contains(name, "cvs") {
		reasons = append(reasons, ReasonDev)
	}
	if luarocksPre.MatchString(name) {
		reasons = append(reasons, ReasonPrerelease)
	}
	return verdict(reasons...)
}

// ── Clojars (Maven ordering, Leiningen conventions) ─────────────────────────

type clojarsAlgo struct{}

func (clojarsAlgo) compare(a, b string) (int, bool) {
	return mavenAlgo{}.compare(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v"))
}

// classify: Clojars files every non-release qualifier under prerelease (there is
// no milestone/dev distinction) and does not treat +build as unstable.
func (clojarsAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	orderable, stable, reasons := mavenStability(v)
	if !orderable || stable {
		return orderable, stable, reasons
	}
	out := reasons[:0:0]
	for _, r := range reasons {
		switch r {
		case ReasonBuildMetadata:
		case ReasonMilestone, ReasonDev, ReasonNightly:
			out = append(out, ReasonPrerelease)
		default:
			out = append(out, r)
		}
	}
	return verdict(dedupe(out)...)
}

// ── ZeroVer ─────────────────────────────────────────────────────────────────

// zeroverAlgo is SemVer with one exception the vectors record: OpenSSL-style
// 0.9.8n is stable but cannot be ordered by a SemVer parser.
type zeroverAlgo struct{ semverAlgo }

var zeroverLetter = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+[a-z]$`)

func (z zeroverAlgo) classify(v string) (bool, bool, []string) {
	if zeroverLetter.MatchString(v) {
		return false, true, nil
	}
	return z.semverAlgo.classify(v)
}

// ── opam (Debian-style ordering) ────────────────────────────────────────────

type opamAlgo struct{}

var opamValid = regexp.MustCompile(`^[A-Za-z0-9~][A-Za-z0-9.+_~-]*$`)
var opamPre = regexp.MustCompile(`(?i)(^|[^A-Za-z])(alpha|beta|rc|pre)([0-9]*)([^A-Za-z]|$)`)
var opamGit = regexp.MustCompile(`(?i)(^|[^A-Za-z])git[0-9a-f]*([^A-Za-z]|$)`)

func opamSplit(v string) (upstream, revision string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func (opamAlgo) compare(a, b string) (int, bool) {
	if !opamValid.MatchString(a) || !opamValid.MatchString(b) {
		return 0, false
	}
	ua, ra := opamSplit(a)
	ub, rb := opamSplit(b)
	if c := debVerrevcmp(ua, ub); c != 0 {
		return c, true
	}
	return debVerrevcmp(ra, rb), true
}

func (opamAlgo) classify(v string) (bool, bool, []string) {
	if !opamValid.MatchString(v) {
		return unparseable()
	}
	var reasons []string
	if strings.Contains(v, "~") || opamPre.MatchString(v) {
		reasons = append(reasons, ReasonPrerelease)
	}
	reasons = append(reasons, channelReasons(v)...)
	if opamGit.MatchString(v) {
		reasons = append(reasons, ReasonDev)
	}
	if v == "dev" || v == "master" {
		reasons = append(reasons, ReasonDev, ReasonBranchRef)
	}
	return verdict(dedupe(reasons)...)
}

// ── Homebrew (Version / PkgVersion) ─────────────────────────────────────────

type homebrewAlgo struct{}

var (
	homebrewRev  = regexp.MustCompile(`^(.*)_([0-9]+)$`)
	homebrewTok  = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)
	homebrewWord = map[string]int{"alpha": -4, "a": -4, "beta": -3, "b": -3, "pre": -2, "rc": -1, "patch": 1, "post": 1, "p": 1}
)

type homebrewTokenV struct {
	n    int
	rank int
	num  bool
}

// homebrewParse splits a Homebrew version into tokens and a trailing _N
// revision. HEAD outranks every numbered version.
func homebrewParse(v string) (toks []homebrewTokenV, rev int, head, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, 0, false, false
	}
	if v == "HEAD" || strings.HasPrefix(v, "HEAD-") {
		return nil, 0, true, true
	}
	if m := homebrewRev.FindStringSubmatch(v); m != nil {
		v = m[1]
		rev, _ = strconv.Atoi(m[2])
	}
	for _, t := range homebrewTok.FindAllString(v, -1) {
		if n, err := strconv.Atoi(t); err == nil {
			toks = append(toks, homebrewTokenV{n: n, num: true})
			continue
		}
		r, known := homebrewWord[strings.ToLower(t)]
		if !known {
			r = 2 // unknown words (dev, nightly) sort above the release
		}
		toks = append(toks, homebrewTokenV{rank: r})
	}
	return toks, rev, false, len(toks) > 0
}

func (homebrewAlgo) compare(a, b string) (int, bool) {
	ta, ra, ha, ok := homebrewParse(a)
	if !ok {
		return 0, false
	}
	tb, rb, hb, ok := homebrewParse(b)
	if !ok {
		return 0, false
	}
	if ha || hb {
		return cmpInt(boolInt(ha), boolInt(hb)), true
	}
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var x, y homebrewTokenV
		hx, hy := i < len(ta), i < len(tb)
		if hx {
			x = ta[i]
		}
		if hy {
			y = tb[i]
		}
		switch {
		case !hx && y.num:
			if y.n != 0 {
				return -1, true
			}
			continue
		case !hy && x.num:
			if x.n != 0 {
				return 1, true
			}
			continue
		case !hx:
			return cmpInt(0, y.rank), true
		case !hy:
			return cmpInt(x.rank, 0), true
		case x.num && y.num:
			if x.n != y.n {
				return cmpInt(x.n, y.n), true
			}
		case x.num:
			return 1, true
		case y.num:
			return -1, true
		default:
			if x.rank != y.rank {
				return cmpInt(x.rank, y.rank), true
			}
		}
	}
	return cmpInt(ra, rb), true
}

var homebrewPreRe = regexp.MustCompile(`(?i)(^|[^A-Za-z])(alpha|beta|pre|rc)|[0-9](a|b|rc)[0-9]`)

func (homebrewAlgo) classify(v string) (bool, bool, []string) {
	toks, _, head, ok := homebrewParse(v)
	if !ok {
		return unparseable()
	}
	if head {
		return verdict(ReasonGitSnapshot)
	}
	_ = toks
	var reasons []string
	if homebrewPreRe.MatchString(v) {
		reasons = append(reasons, ReasonPrerelease)
	}
	for _, r := range channelReasons(v) {
		if r == ReasonSnapshot {
			r = ReasonDev
		}
		reasons = append(reasons, r)
	}
	return verdict(dedupe(reasons)...)
}

// ── vcpkg variants ──────────────────────────────────────────────────────────

type vcpkgDateAlgo struct{}

var vcpkgDateRe = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2})((?:\.(?:0|[1-9][0-9]*))*)$`)

func (vcpkgDateAlgo) compare(a, b string) (int, bool) {
	ma, mb := vcpkgDateRe.FindStringSubmatch(a), vcpkgDateRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	if c := strings.Compare(ma[1], mb[1]); c != 0 {
		return c, true
	}
	return cmpIntLists(strings.FieldsFunc(ma[2], func(r rune) bool { return r == '.' }),
		strings.FieldsFunc(mb[2], func(r rune) bool { return r == '.' })), true
}

func (vcpkgDateAlgo) classify(v string) (bool, bool, []string) {
	if !vcpkgDateRe.MatchString(v) {
		return unparseable()
	}
	return verdict()
}

// vcpkgStringAlgo is the opaque version-string scheme: stable by definition,
// never orderable.
type vcpkgStringAlgo struct{}

func (vcpkgStringAlgo) compare(a, b string) (int, bool) { return 0, false }
func (vcpkgStringAlgo) classify(v string) (bool, bool, []string) {
	return false, v != "", nil
}

// vcpkgPortAlgo orders version#port-version: the version first, then the port.
type vcpkgPortAlgo struct{}

func (vcpkgPortAlgo) compare(a, b string) (int, bool) {
	va, pa, _ := strings.Cut(a, "#")
	vb, pb, _ := strings.Cut(b, "#")
	c, ok := registry["vcpkg"].compare(va, vb)
	if !ok || c != 0 {
		return c, ok
	}
	na, _ := strconv.Atoi(pa)
	nb, _ := strconv.Atoi(pb)
	return cmpInt(na, nb), true
}

func (vcpkgPortAlgo) classify(v string) (bool, bool, []string) {
	base, _, _ := strings.Cut(v, "#")
	return registry["vcpkg"].classify(base)
}
