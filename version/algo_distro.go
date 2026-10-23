package version

import (
	"regexp"
	"strconv"
	"strings"
)

// ── shared distro stability ─────────────────────────────────────────────────
//
// A distro revision (-1ubuntu0.22.04.1, +deb11u1, .el9_3, -r3) is a rebuild of a
// release and stays stable. Only a pre-release word, a VCS or date snapshot, a
// nightly/dev marker, or a tilde that is not one of the stable backport tokens
// makes a version unstable.

var (
	distroPreWord  = regexp.MustCompile(`(?i)(^|[^A-Za-z])(alpha|beta|rc|pre|preview|prerelease|milestone|candidate)([._-]?[0-9]+)?([^A-Za-z]|$)`)
	distroVCS      = regexp.MustCompile(`(?i)(^|[^A-Za-z])(git|svn|hg|bzr|cvs|darcs)([0-9a-f]{0,40})([._+~^-]|$)`)
	distroDescribe = regexp.MustCompile(`\.g[0-9a-f]{7,40}$`)
	distroNightly  = regexp.MustCompile(`(?i)(^|[^A-Za-z])nightly([^A-Za-z]|$)`)
	distroDev      = regexp.MustCompile(`(?i)(^|[^A-Za-z])(dev|devel|snapshot|canary|unstable)([._-]?[0-9]+)?([^A-Za-z]|$)`)
	distroDate     = regexp.MustCompile(`[+~^.](19|20)[0-9]{6}([.+~^-]|$)`)
	tildeStable    = regexp.MustCompile(`^(?i)(bpo[0-9]+|deb[0-9]+u?[0-9]*|[0-9]{2}\.[0-9]{2}|ubuntu[0-9]|esm[0-9]*|backport)`)
	fedoraRelease0 = regexp.MustCompile(`^0(\.|$)`)
	fedoraGitHash  = regexp.MustCompile(`[0-9]{8}g[0-9a-f]{7,}`)
)

type distroRules struct {
	tilde          bool // a '~' is a pre-release marker unless it names a stable backport
	caret          bool // a '^' marks a post-release snapshot (rpm)
	fedoraRelease0 bool // release field 0.N is a pre-release by Fedora's old convention
}

func distroUnstable(v, release string, r distroRules) []string {
	var reasons []string
	add := func(s string) {
		for _, x := range reasons {
			if x == s {
				return
			}
		}
		reasons = append(reasons, s)
	}
	if distroPreWord.MatchString(v) {
		add(ReasonPrerelease)
	}
	if distroVCS.MatchString(v) || distroDescribe.MatchString(v) || (r.caret && fedoraGitHash.MatchString(v)) {
		add(ReasonGitSnapshot)
	}
	if r.caret && strings.Contains(v, "^") {
		add(ReasonSnapshot)
	}
	if distroNightly.MatchString(v) {
		add(ReasonNightly)
	}
	if distroDev.MatchString(v) {
		add(ReasonDev)
	}
	if distroDate.MatchString(v) {
		add(ReasonSnapshot)
	}
	if r.fedoraRelease0 && release != "" && fedoraRelease0.MatchString(release) {
		add(ReasonPrerelease)
	}
	// A tilde that is not a stable backport token and has no more specific
	// explanation is a plain pre-release marker.
	if r.tilde && len(reasons) == 0 {
		for i := 0; i < len(v); i++ {
			if v[i] == '~' && !tildeStable.MatchString(v[i+1:]) {
				add(ReasonPrerelease)
				break
			}
		}
	}
	return reasons
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// splitEVR splits [epoch:]version[-release]; epoch defaults to "0".
func splitEVR(v string) (epoch, version, release string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i > 0 && digitsRe.MatchString(v[:i]) {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// ── Debian / dpkg ───────────────────────────────────────────────────────────

type debianAlgo struct{}

var debianValid = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9][A-Za-z0-9.+~:-]*$`)

// debianWellFormed rejects what dpkg's parseversion rejects: nothing after the epoch
// colon, or an empty revision after the last hyphen.
func debianWellFormed(v string) bool {
	if !debianValid.MatchString(v) || strings.HasSuffix(v, "-") || strings.HasSuffix(v, ":") {
		return false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 && !digitsRe.MatchString(v[:i]) {
		return false
	}
	return true
}

func debOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// debVerrevcmp is dpkg's verrevcmp (lib/dpkg/version.c).
func debVerrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(a, i), debOrder(b, j)
			if ac != bc {
				return clamp(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return clamp(firstDiff)
		}
	}
	return 0
}

func (debianAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !debianWellFormed(a) || !debianWellFormed(b) {
		return 0, false
	}
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := cmpDigits(trimZeros(ea), trimZeros(eb)); c != 0 {
		return c, true
	}
	if c := debVerrevcmp(va, vb); c != 0 {
		return c, true
	}
	return debVerrevcmp(ra, rb), true
}

func (debianAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if !debianWellFormed(v) {
		return unparseable()
	}
	_, ver, rel := splitEVR(v)
	return verdict(distroUnstable(ver+"-"+rel, rel, distroRules{tilde: true})...)
}

// ── RPM ─────────────────────────────────────────────────────────────────────

type rpmAlgo struct{}

var rpmValid = regexp.MustCompile(`^([0-9]+:)?[0-9A-Za-z][A-Za-z0-9._+~^-]*$`)

func rpmWellFormed(v string) bool { return rpmValid.MatchString(v) && strings.Count(v, "-") <= 1 }

// rpmvercmp is rpm's rpmio/rpmvercmp.cc, including ~ (sorts before everything)
// and ^ (sorts after end of string but before any other segment).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ca, cb := at(a, i), at(b, j)
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == '^' || cb == '^' {
			if ca == 0 {
				return -1
			}
			if cb == 0 {
				return 1
			}
			if ca != '^' {
				return 1
			}
			if cb != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == 0 || cb == 0 {
			break
		}
		s1, s2 := i, j
		isnum := isDigit(ca)
		if isnum {
			for s1 < len(a) && isDigit(a[s1]) {
				s1++
			}
			for s2 < len(b) && isDigit(b[s2]) {
				s2++
			}
		} else {
			for s1 < len(a) && isAlpha(a[s1]) {
				s1++
			}
			for s2 < len(b) && isAlpha(b[s2]) {
				s2++
			}
		}
		if i == s1 {
			return -1
		}
		if j == s2 {
			if isnum {
				return 1
			}
			return -1
		}
		x, y := a[i:s1], b[j:s2]
		if isnum {
			x, y = trimZeros(x), trimZeros(y)
			if len(x) != len(y) {
				if len(x) > len(y) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
		i, j = s1, s2
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i < len(a) {
		return 1
	}
	return -1
}

func (rpmAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !rpmWellFormed(a) || !rpmWellFormed(b) {
		return 0, false
	}
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := cmpDigits(trimZeros(ea), trimZeros(eb)); c != 0 {
		return c, true
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, true
	}
	if ra == "" || rb == "" {
		return 0, true
	}
	return rpmvercmp(ra, rb), true
}

func (rpmAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if !rpmWellFormed(v) {
		return unparseable()
	}
	_, ver, rel := splitEVR(v)
	return verdict(distroUnstable(ver+"-"+rel, rel, distroRules{tilde: true, caret: true, fedoraRelease0: true})...)
}

// ── Arch (libalpm vercmp, an rpm 4.8.1 derivative) ──────────────────────────

type archAlgo struct{}

var (
	archValid = regexp.MustCompile(`^([0-9]+:)?[0-9A-Za-z][A-Za-z0-9._+~^-]*$`)
	archRel   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

func archWellFormed(v string) bool {
	if !archValid.MatchString(v) {
		return false
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return !strings.Contains(v[i+1:], "-") && archRel.MatchString(v[i+1:])
	}
	return true
}

func archRpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for one < len(a) && two < len(b) {
		p1, p2 := one, two
		for one < len(a) && !isAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) {
			two++
		}
		if one >= len(a) || two >= len(b) {
			break
		}
		if one-p1 != two-p2 {
			if one-p1 < two-p2 {
				return -1
			}
			return 1
		}
		s1, s2 := one, two
		isnum := isDigit(a[s1])
		if isnum {
			for s1 < len(a) && isDigit(a[s1]) {
				s1++
			}
			for s2 < len(b) && isDigit(b[s2]) {
				s2++
			}
		} else {
			for s1 < len(a) && isAlpha(a[s1]) {
				s1++
			}
			for s2 < len(b) && isAlpha(b[s2]) {
				s2++
			}
		}
		if one == s1 {
			return -1
		}
		if two == s2 {
			if isnum {
				return 1
			}
			return -1
		}
		x, y := a[one:s1], b[two:s2]
		if isnum {
			x, y = trimZeros(x), trimZeros(y)
			if len(x) != len(y) {
				if len(x) > len(y) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
		one, two = s1, s2
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	ca, cb := at(a, one), at(b, two)
	if (ca == 0 && !isAlpha(cb)) || isAlpha(ca) {
		return -1
	}
	return 1
}

func (archAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !archWellFormed(a) || !archWellFormed(b) {
		return 0, false
	}
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := cmpDigits(trimZeros(ea), trimZeros(eb)); c != 0 {
		return c, true
	}
	if c := archRpmvercmp(va, vb); c != 0 {
		return c, true
	}
	if ra == "" || rb == "" {
		return 0, true
	}
	return archRpmvercmp(ra, rb), true
}

var archSnapshot = regexp.MustCompile(`(^|[^A-Za-z0-9])r[0-9]+\.[0-9a-f]{6,}|\.r[0-9]+\.g[0-9a-f]+`)

func (archAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if !archWellFormed(v) {
		return unparseable()
	}
	_, ver, _ := splitEVR(v)
	reasons := distroUnstable(ver, "", distroRules{})
	if archSnapshot.MatchString(ver) {
		reasons = append(reasons, ReasonGitSnapshot)
	}
	return verdict(dedupe(reasons)...)
}

// ── Alpine apk and Gentoo ebuild ────────────────────────────────────────────
//
// Both use  digits(.digits)*[letter](_suffix[digits])*[-rN]  and differ in the
// suffix set. Alpine's C apk-tools and Wolfi's go-apk disagree on leading zeros
// and on 1.0 vs 1.0-r0; wolfi sets lenient.

type apkAlgo struct {
	name string
	// suffixes lists suffix names low to high around the release position.
	pre  []string // below the bare version
	post []string // above the bare version
	// tilde accepts apk v3's ~hash after the suffixes.
	tilde bool
	// lenient treats leading-zero components as integers and r0 as absent.
	lenient bool
	// ebuildLive marks 9999 as a live ebuild (gentoo).
	ebuildLive bool
	// strictSuffixes allows at most one pre and one post suffix (go-apk).
	strictSuffixes bool
}

var (
	alpineAlgoV  = apkAlgo{name: "alpine", pre: []string{"alpha", "beta", "pre", "rc"}, post: []string{"cvs", "svn", "git", "hg", "p"}, tilde: true}
	wolfiAlgoV   = apkAlgo{name: "wolfi", pre: []string{"alpha", "beta", "pre", "rc"}, post: []string{"cvs", "svn", "git", "hg", "p"}, lenient: true, strictSuffixes: true}
	gentooAlgoV  = apkAlgo{name: "gentoo", pre: []string{"alpha", "beta", "pre", "rc"}, post: []string{"p"}, ebuildLive: true}
	apkSuffixRe  = regexp.MustCompile(`^_([a-z]+)([0-9]*)`)
	apkVersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*[a-z]?((_[a-z]+[0-9]*)*)(~[0-9a-f]+)?(-r[0-9]+)?$`)
)

type apkVer struct {
	nums     []string
	letter   string
	suffixes []apkSuffix
	hash     string
	rev      int // -1 when absent
}

type apkSuffix struct {
	rank int // negative below the release, positive above
	num  int
	name string
}

func (a apkAlgo) parse(v string) (apkVer, bool) {
	out := apkVer{rev: -1}
	v = strings.TrimSpace(v)
	if v == "" || !apkVersionRe.MatchString(v) {
		return out, false
	}
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		n, err := strconv.Atoi(v[i+2:])
		if err != nil {
			return out, false
		}
		out.rev = n
		v = v[:i]
	}
	if i := strings.IndexByte(v, '~'); i >= 0 {
		if !a.tilde {
			return out, false
		}
		out.hash = v[i+1:]
		v = v[:i]
	}
	// numeric core and optional letter
	i := 0
	for i < len(v) && (isDigit(v[i]) || v[i] == '.') {
		i++
	}
	core := v[:i]
	v = v[i:]
	out.nums = strings.Split(core, ".")
	if len(v) > 0 && v[0] >= 'a' && v[0] <= 'z' {
		out.letter = v[:1]
		v = v[1:]
	}
	for v != "" {
		m := apkSuffixRe.FindStringSubmatch(v)
		if m == nil {
			return out, false
		}
		rank, found := 0, false
		for k, s := range a.pre {
			if s == m[1] {
				rank, found = k-len(a.pre), true
			}
		}
		for k, s := range a.post {
			if s == m[1] {
				rank, found = k+1, true
			}
		}
		if !found {
			return out, false
		}
		n := 0
		if m[2] != "" {
			n, _ = strconv.Atoi(m[2])
		}
		out.suffixes = append(out.suffixes, apkSuffix{rank: rank, num: n, name: m[1]})
		v = v[len(m[0]):]
	}
	if a.strictSuffixes {
		pres, posts := 0, 0
		for _, sfx := range out.suffixes {
			if sfx.rank < 0 {
				pres++
			} else {
				posts++
			}
		}
		if pres > 1 || posts > 1 {
			return out, false
		}
	}
	return out, true
}

func (a apkAlgo) cmpNum(x, y string) int {
	if !a.lenient && (len(x) > 1 && x[0] == '0' || len(y) > 1 && y[0] == '0') {
		return clamp(strings.Compare(x, y))
	}
	return cmpDigits(trimZeros(x), trimZeros(y))
}

func (a apkAlgo) compare(x, y string) (int, bool) {
	vx, ok := a.parse(x)
	if !ok {
		return 0, false
	}
	vy, ok := a.parse(y)
	if !ok {
		return 0, false
	}
	n := len(vx.nums)
	if len(vy.nums) > n {
		n = len(vy.nums)
	}
	for i := 0; i < n; i++ {
		switch {
		case i >= len(vx.nums):
			return -1, true
		case i >= len(vy.nums):
			return 1, true
		}
		if c := a.cmpNum(vx.nums[i], vy.nums[i]); c != 0 {
			return c, true
		}
	}
	if c := strings.Compare(vx.letter, vy.letter); c != 0 {
		return c, true
	}
	for i := 0; i < len(vx.suffixes) || i < len(vy.suffixes); i++ {
		sx, sy := apkSuffix{}, apkSuffix{}
		if i < len(vx.suffixes) {
			sx = vx.suffixes[i]
		}
		if i < len(vy.suffixes) {
			sy = vy.suffixes[i]
		}
		if sx.rank != sy.rank {
			return cmpInt(sx.rank, sy.rank), true
		}
		if sx.num != sy.num {
			return cmpInt(sx.num, sy.num), true
		}
	}
	if c := strings.Compare(vx.hash, vy.hash); c != 0 {
		return c, true
	}
	rx, ry := vx.rev, vy.rev
	if a.lenient {
		rx, ry = max(rx, 0), max(ry, 0)
	}
	return cmpInt(rx, ry), true
}

func (a apkAlgo) classify(v string) (bool, bool, []string) {
	p, ok := a.parse(v)
	if !ok {
		return unparseable()
	}
	var reasons []string
	for _, s := range p.suffixes {
		switch s.name {
		case "alpha", "beta", "pre", "rc":
			reasons = append(reasons, ReasonPrerelease)
		case "cvs", "svn", "git", "hg":
			reasons = append(reasons, ReasonGitSnapshot)
		}
	}
	if p.hash != "" {
		reasons = append(reasons, ReasonGitSnapshot)
	}
	if a.ebuildLive {
		for _, n := range p.nums {
			if n == "9999" || n == "99999999" {
				reasons = append(reasons, ReasonSnapshot)
			}
		}
	}
	// Gentoo _p<date> is a snapshot by devmanual convention; _p1 is a patch level.
	if a.ebuildLive {
		for _, s := range p.suffixes {
			if s.name == "p" && s.num >= 19000101 {
				reasons = append(reasons, ReasonSnapshot)
			}
		}
	}
	return verdict(dedupe(reasons)...)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── Nix (builtins.compareVersions) ──────────────────────────────────────────

type nixAlgo struct{}

var nixValid = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]*$`)

func nixComponents(v string) []string {
	var out []string
	for i := 0; i < len(v); {
		if v[i] == '.' || v[i] == '-' {
			i++
			continue
		}
		j := i
		if isDigit(v[i]) {
			for j < len(v) && isDigit(v[j]) {
				j++
			}
		} else {
			for j < len(v) && !isDigit(v[j]) && v[j] != '.' && v[j] != '-' {
				j++
			}
		}
		out = append(out, v[i:j])
		i = j
	}
	return out
}

func nixLess(c1, c2 string) bool {
	n1, e1 := strconv.Atoi(c1)
	n2, e2 := strconv.Atoi(c2)
	isN1, isN2 := e1 == nil && c1 != "", e2 == nil && c2 != ""
	switch {
	case isN1 && isN2:
		return n1 < n2
	case c1 == "" && isN2:
		return true
	case c1 == "pre" && c2 != "pre":
		return true
	case c2 == "pre":
		return false
	case isN1:
		return false
	case isN2:
		return true
	}
	return c1 < c2
}

func (nixAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !nixValid.MatchString(a) || !nixValid.MatchString(b) {
		return 0, false
	}
	ca, cb := nixComponents(a), nixComponents(b)
	for i := 0; i < len(ca) || i < len(cb); i++ {
		x, y := "", ""
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if nixLess(x, y) {
			return -1, true
		}
		if nixLess(y, x) {
			return 1, true
		}
	}
	return 0, true
}

var nixUnstable = regexp.MustCompile(`(?i)(^|[^A-Za-z])unstable([^A-Za-z]|$)`)

func (nixAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if !nixValid.MatchString(v) {
		return unparseable()
	}
	reasons := distroUnstable(v, "", distroRules{})
	if nixUnstable.MatchString(v) {
		// <last release>-unstable-<date> snapshots the default branch; the word
		// is not a dev-channel marker here.
		kept := reasons[:0]
		for _, r := range reasons {
			if r != ReasonDev {
				kept = append(kept, r)
			}
		}
		reasons = append(kept, ReasonGitSnapshot)
	}
	return verdict(dedupe(reasons)...)
}

// ── Bitnami ─────────────────────────────────────────────────────────────────
//
// X.Y.Z[-N][+meta]: the -N is a rebuild counter and ranks ABOVE the bare
// version; a word after the hyphen (rc1) also ranks above it in Bitnami's own
// comparer, but is a pre-release.

type bitnamiAlgo struct{}

var bitnamiRevision = regexp.MustCompile(`^(?:[a-z]+-[0-9]+(?:\.[0-9]+)*-)?r[0-9]+$`)

var bitnamiRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

func (bitnamiAlgo) compare(a, b string) (int, bool) {
	ma := bitnamiRe.FindStringSubmatch(strings.TrimSpace(a))
	mb := bitnamiRe.FindStringSubmatch(strings.TrimSpace(b))
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		if c := cmpDigits(trimZeros(ma[i]), trimZeros(mb[i])); c != 0 {
			return c, true
		}
	}
	switch {
	case ma[4] == "" && mb[4] == "":
		return 0, true
	case ma[4] == "":
		return -1, true
	case mb[4] == "":
		return 1, true
	}
	if digitsRe.MatchString(ma[4]) && digitsRe.MatchString(mb[4]) {
		return cmpDigits(trimZeros(ma[4]), trimZeros(mb[4])), true
	}
	return clamp(strings.Compare(ma[4], mb[4])), true
}

func (bitnamiAlgo) classify(v string) (bool, bool, []string) {
	m := bitnamiRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return unparseable()
	}
	rev := m[4]
	if rev == "" || digitsRe.MatchString(rev) || bitnamiRevision.MatchString(rev) {
		return verdict()
	}
	var reasons []string
	if distroVCS.MatchString(rev) {
		reasons = append(reasons, ReasonGitSnapshot)
	}
	for _, r := range channelReasons(rev) {
		// Bitnami files a snapshot build under dev.
		if r == ReasonSnapshot {
			r = ReasonDev
		}
		reasons = append(reasons, r)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, ReasonPrerelease)
	}
	return verdict(dedupe(reasons)...)
}
