package version

import (
	"regexp"
	"strings"
)

// Recency-family engines. These schemes have no single reference comparator: a
// version is a tag, a build label or a channel name, and only some strings in
// each scheme can be ordered at all. Every engine therefore answers
// compare(..., ok=false) for the strings it cannot order (floating tags,
// branches, digests) instead of falling back to string order, and marks them
// unstable with the reason that names why.

func init() {
	registry["apple"] = appleAlgo{}
	registry["backport-branches"] = semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 4, leadingZeros: true}}
	registry["browser-extension"] = extensionAlgo{}
	registry["calver"] = calverAlgo{}
	registry["chocolatey"] = semverRecency{
		semverAlgo: semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 1, maxParts: 4, foldCase: true, leadingZeros: true, noPreLeadingZeros: true, maxNum: "2147483647"}},
		reasons: func(p semverVer) []string {
			return preWords(p, wordTable{"nightly": {ReasonNightly}, "dev": {ReasonDev}, "ci": {ReasonDev}, "snapshot": {ReasonSnapshot}}, false)
		},
	}
	registry["db-majorminor"] = dbAlgo{}
	registry["docker"] = dockerAlgo{}
	registry["git-ref"] = gitRefAlgo{}
	registry["github-release"] = githubAlgo{}
	registry["go-toolchain"] = goToolchainAlgo{}
	registry["java"] = javaAlgo{}
	registry["jetbrains"] = semverRecency{
		semverAlgo: semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 4, leadingZeros: true}},
		reasons: func(p semverVer) []string {
			return preWords(p, wordTable{"snapshot": {ReasonSnapshot}, "nightly": {ReasonNightly}}, true)
		},
		names: func(v string) (bool, bool, []string) {
			lv := strings.ToLower(v)
			switch {
			case strings.Contains(lv, "snapshot"):
				if strings.HasPrefix(lv, "latest") {
					return false, false, []string{ReasonSnapshot, ReasonFloatingTag}
				}
				return false, false, []string{ReasonSnapshot}
			case strings.HasSuffix(v, ".*"):
				return false, false, []string{ReasonFloatingTag}
			}
			return unparseable()
		},
	}
	registry["letter-suffix"] = letterSuffixAlgo{}
	registry["linux-kernel"] = kernelAlgo{}
	registry["nodejs"] = semverRecency{
		semverAlgo: semverAlgo{semverOpts{vPrefix: "optional", minParts: 3, maxParts: 3}},
		reasons: func(p semverVer) []string {
			return preWords(p, wordTable{"nightly": {ReasonNightly}, "canary": {ReasonCanary}, "test": {ReasonDev}}, false)
		},
		names: floatingName,
	}
	registry["npm-dist-tag"] = semverRecency{
		semverAlgo: semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3}},
		reasons:    npmPreReasons,
		names:      npmTagName,
	}
	registry["openssl"] = opensslAlgo{}
	registry["php"] = phpAlgo{}
	registry["python-runtime"] = pythonRuntimeAlgo{}
	registry["rust-toolchain"] = rustAlgo{}
	registry["scoop"] = scoopAlgo{}
	registry["ubuntu"] = ubuntuAlgo{}
	registry["unity"] = unityAlgo{}
	registry["vscode"] = semverRecency{
		semverAlgo: semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3}},
		reasons:    vscodeReasons,
	}
	registry["windows-version"] = windowsAlgo{}
	registry["winget"] = wingetAlgo{}
	registry["android"] = androidAlgo{}
	registry["linux"] = linuxAlgo{}
}

// ── shared helpers ──────────────────────────────────────────────────────────

// tokens splits s into lower-case letter runs and digit runs.
func tokens(s string) []string {
	return channelTokenRe.FindAllString(strings.ToLower(s), -1)
}

// wordTable maps a lower-case word to the reasons it implies.
type wordTable map[string][]string

func (t wordTable) reasons(s string) []string {
	var out []string
	for _, tok := range tokens(s) {
		out = append(out, t[tok]...)
	}
	return dedupe(out)
}

// preWords turns a parsed pre-release into reasons: the words found in it, or
// plain prerelease when none matched. With dateIsNightly, an identifier that is
// a whole date (20240101) marks a nightly build.
func preWords(p semverVer, t wordTable, dateIsNightly bool) []string {
	if !p.hasP {
		return nil
	}
	pre := strings.Join(p.pre, ".")
	out := t.reasons(pre)
	if dateIsNightly {
		for _, id := range p.pre {
			if dateStampRe.MatchString(id) {
				out = append(out, ReasonNightly)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, ReasonPrerelease)
	}
	return dedupe(out)
}

var dateStampRe = regexp.MustCompile(`^(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$`)

// nameRe matches a bare channel or codename tag (latest, lts, krypton, noble).
var nameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/_.*-]*$`)

// floatingName judges a bare name no version parser accepted: a moving pointer.
func floatingName(v string) (bool, bool, []string) {
	if nameRe.MatchString(v) {
		return false, false, []string{ReasonFloatingTag}
	}
	return unparseable()
}

// dotNums splits "1.2.3" into digit strings without leading zeros.
func dotNums(s string) ([]string, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	for i, p := range parts {
		if !digitsRe.MatchString(p) {
			return nil, false
		}
		parts[i] = trimZeros(p)
	}
	return parts, true
}

// cmpTuple orders two numeric tuples; a missing trailing field counts as 0.
func cmpTuple(a, b []string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpDigits(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// cmpTokens compares token lists: numbers numerically and below words, words
// lexically, a prefix below its extension.
func cmpTokens(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xd, yd := isDigit(x[0]), isDigit(y[0])
		switch {
		case xd && yd:
			if c := cmpDigits(trimZeros(x), trimZeros(y)); c != 0 {
				return c
			}
		case xd:
			return -1
		case yd:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

// preRanks puts pre-release words on one scale. Rank 0 is the release itself,
// so anything negative sorts before it and a post-release word sorts after.
var preRanks = map[string]int{
	"dev": -5, "devel": -5, "snapshot": -5, "nightly": -5, "canary": -5,
	"experimental": -5, "ci": -5, "test": -5, "internal": -5,
	"alpha": -4, "a": -4,
	"beta": -3, "b": -3, "eap": -3,
	"preview": -2, "pre": -2,
	"rc": -1, "c": -1,
	"post": 2, "pl": 2, "p": 2,
}

// preKey is a rank plus the tokens after the rank word ("beta.2" is -3, [2]).
type preKey struct {
	rank int
	rest []string
}

func parsePre(s string) preKey {
	toks := tokens(s)
	if len(toks) > 0 && !isDigit(toks[0][0]) {
		if r, ok := preRanks[toks[0]]; ok {
			return preKey{r, toks[1:]}
		}
	}
	return preKey{-3, toks}
}

func (a preKey) cmp(b preKey) int {
	if a.rank != b.rank {
		return cmpInt(a.rank, b.rank)
	}
	return cmpTokens(a.rest, b.rest)
}

// semverRecency reuses the semver parser and comparator and replaces only the
// stability rule, which these registries define by channel words rather than by
// the presence of a pre-release part.
type semverRecency struct {
	semverAlgo
	// reasons maps a parsed version to its unstable reasons (nil when stable).
	reasons func(p semverVer) []string
	// names judges a string the semver parser rejected; nil means unparseable.
	names func(v string) (bool, bool, []string)
}

func (s semverRecency) classify(v string) (bool, bool, []string) {
	p, ok := s.parse(v)
	if !ok {
		if s.names != nil {
			return s.names(v)
		}
		return unparseable()
	}
	return verdict(dedupe(s.reasons(p))...)
}

// hexRe matches an abbreviated or full git object name or content hash.
var hexRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func isDigest(v string) bool {
	return hexRe.MatchString(v) && strings.ContainsAny(v, "abcdef") && strings.ContainsAny(v, "0123456789")
}

// ── apple ───────────────────────────────────────────────────────────────────

// Marketing versions (17.2.1) are numeric tuples. Build labels (21C62) order
// by train, minor-train letter and number, but only within one platform, so
// they are reported as not orderable while still comparing with each other.
type appleAlgo struct{}

var (
	appleMarketing = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
	appleBuild     = regexp.MustCompile(`^(\d{2})([A-Z])(\d+)([a-z]?)$`)
	appleRSR       = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)? \([a-z]\)$`)
	applePre       = regexp.MustCompile(`(?i)^\d+\.\d+(?:\.\d+)? (?:beta|rc|dp)(?: \d+)?$`)
)

func (appleAlgo) classify(v string) (bool, bool, []string) {
	switch {
	case appleMarketing.MatchString(v):
		return verdict()
	case appleBuild.MatchString(v):
		// A lower-case suffix on the build marks a developer seed.
		if m := appleBuild.FindStringSubmatch(v); m[4] != "" {
			return false, false, []string{ReasonPrerelease}
		}
		return false, true, nil
	case appleRSR.MatchString(v):
		// Rapid Security Response "(a)" has no numeric tuple.
		return false, true, nil
	case applePre.MatchString(v):
		return false, false, []string{ReasonPrerelease}
	}
	return unparseable()
}

func (appleAlgo) compare(a, b string) (int, bool) {
	if appleMarketing.MatchString(a) && appleMarketing.MatchString(b) {
		na, _ := dotNums(a)
		nb, _ := dotNums(b)
		return cmpTuple(na, nb), true
	}
	ma, mb := appleBuild.FindStringSubmatch(a), appleBuild.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	if c := strings.Compare(ma[1], mb[1]); c != 0 {
		return c, true
	}
	if c := strings.Compare(ma[2], mb[2]); c != 0 {
		return c, true
	}
	// Seeds carry the larger sequence numbers but precede the release build.
	if (ma[4] == "") != (mb[4] == "") {
		if ma[4] != "" {
			return -1, true
		}
		return 1, true
	}
	return cmpDigits(trimZeros(ma[3]), trimZeros(mb[3])), true
}

// ── browser-extension ───────────────────────────────────────────────────────

// Chrome and Edge manifests allow one to four integers of at most 65535 and
// reject an all-zero version. The legacy Firefox toolkit form (1.0b2) is the
// only way a pre-release shows up in a version string.
type extensionAlgo struct{}

var extensionRe = regexp.MustCompile(`^((?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,3})(?:(a|b|pre|rc)(\d+))?$`)

func parseExtension(v string) ([]string, preKey, bool, bool) {
	m := extensionRe.FindStringSubmatch(v)
	if m == nil {
		return nil, preKey{}, false, false
	}
	nums, _ := dotNums(m[1])
	zero := true
	for _, n := range nums {
		if cmpDigits(n, "65535") > 0 {
			return nil, preKey{}, false, false
		}
		zero = zero && n == "0"
	}
	if zero {
		return nil, preKey{}, false, false
	}
	if m[2] == "" {
		return nums, preKey{}, false, true
	}
	return nums, preKey{preRanks[m[2]], []string{trimZeros(m[3])}}, true, true
}

func (extensionAlgo) classify(v string) (bool, bool, []string) {
	_, _, pre, ok := parseExtension(v)
	if !ok {
		return unparseable()
	}
	if pre {
		return verdict(ReasonPrerelease)
	}
	return verdict()
}

func (extensionAlgo) compare(a, b string) (int, bool) {
	na, pa, _, oka := parseExtension(a)
	nb, pb, _, okb := parseExtension(b)
	if !oka || !okb {
		return 0, false
	}
	if c := cmpTuple(na, nb); c != 0 {
		return c, true
	}
	return pa.cmp(pb), true
}

// ── calver ──────────────────────────────────────────────────────────────────

// CalVer orders as a numeric tuple (the date it encodes) with PEP 440 style
// modifiers, an optional epoch (1!2.0) and the tzdata year-letter form (2024b).
// Leading zeros are accepted because the 0M and 0D forms are common.
type calverAlgo struct{}

var (
	calverRe       = regexp.MustCompile(`^(?:(\d+)!)?(\d+(?:\.\d+)*)(.*)$`)
	calverISORe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	calverStreamRe = regexp.MustCompile(`^[fp]\d+$`)
)

type calverVer struct {
	epoch string
	nums  []string
	pre   preKey
	reas  []string
}

var calverWords = wordTable{"dev": {ReasonDev}, "nightly": {ReasonNightly}, "canary": {ReasonCanary}, "experimental": {ReasonCanary}, "snapshot": {ReasonSnapshot}}

func parseCalver(v string) (calverVer, bool) {
	var out calverVer
	v = strings.TrimSpace(v)
	if calverISORe.MatchString(v) {
		// 2026-10-01 (an Android patch level) is a date, not a pre-release.
		out.epoch = "0"
		for _, f := range strings.Split(v, "-") {
			out.nums = append(out.nums, trimZeros(f))
		}
		return out, true
	}
	m := calverRe.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	out.epoch = trimZeros(m[1])
	if m[1] == "" {
		out.epoch = "0"
	}
	out.nums, _ = dotNums(m[2])
	rest := m[3]
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		rest = rest[:i]
	}
	switch {
	case rest == "":
	case len(out.nums) == 1 && len(rest) == 1 && rest[0] >= 'a' && rest[0] <= 'z':
		// tzdata: the letter counts releases within the year.
		out.pre = preKey{1, []string{rest}}
	case calverStreamRe.MatchString(rest):
		// Unity style 2022.3.10f1: f is the final stream and p a patch of it.
		out.pre = preKey{0, []string{trimZeros(rest[1:])}}
		if rest[0] == 'p' {
			out.pre.rank = 1
		}
	case rest[0] == '-' || rest[0] == '.' && len(rest) > 1 && isAlpha(rest[1]) || isAlpha(rest[0]):
		out.pre = parsePre(rest)
		if out.pre.rank < 0 {
			out.reas = append([]string{ReasonPrerelease}, calverWords.reasons(rest)...)
			// yt-dlp nightlies (2026.9.27.232945.dev0) carry an HHMMSS field.
			if len(out.nums) == 4 && len(m[2]) > 0 && strings.HasPrefix(rest, ".dev") && len(out.nums[3]) == 6 {
				out.reas = []string{ReasonDev, ReasonNightly}
			}
		}
	default:
		return out, false
	}
	return out, true
}

func (calverAlgo) classify(v string) (bool, bool, []string) {
	p, ok := parseCalver(v)
	if !ok {
		return unparseable()
	}
	return verdict(dedupe(p.reas)...)
}

func (calverAlgo) compare(a, b string) (int, bool) {
	pa, oka := parseCalver(a)
	pb, okb := parseCalver(b)
	if !oka || !okb {
		return 0, false
	}
	if c := cmpDigits(pa.epoch, pb.epoch); c != 0 {
		return c, true
	}
	if c := cmpTuple(pa.nums, pb.nums); c != 0 {
		return c, true
	}
	return pa.pre.cmp(pb.pre), true
}

// ── db-majorminor ───────────────────────────────────────────────────────────

// PostgreSQL, MySQL and MariaDB: numeric tuples. PostgreSQL pre-releases are
// glued to the major (17beta1, 18devel) and sort before 17.0. A vendor suffix
// (-MariaDB, -0ubuntu0.22.04.1) is packaging and does not affect stability.
type dbAlgo struct{}

var dbRe = regexp.MustCompile(`^(\d+(?:\.\d+){0,2})(?:(alpha|beta|rc|devel)(\d*)|-(alpha|beta|rc|dmr)(\d*)|-(.+))?$`)

func (dbAlgo) classify(v string) (bool, bool, []string) {
	m := dbRe.FindStringSubmatch(v)
	if m == nil {
		return unparseable()
	}
	switch word := m[2] + m[4]; word {
	case "":
		return verdict()
	case "devel":
		return verdict(ReasonDev)
	default:
		return verdict(ReasonPrerelease)
	}
}

func (dbAlgo) compare(a, b string) (int, bool) {
	ma, mb := dbRe.FindStringSubmatch(a), dbRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	key := func(m []string) ([]string, preKey) {
		nums, _ := dotNums(m[1])
		word, n := m[2], m[3]
		if word == "" {
			word, n = m[4], m[5]
		}
		if word == "" {
			return nums, preKey{}
		}
		rank := preRanks[word]
		if word == "dmr" {
			rank = -3
		}
		return nums, preKey{rank, []string{trimZeros0(n)}}
	}
	na, pa := key(ma)
	nb, pb := key(mb)
	if c := cmpTuple(na, nb); c != 0 {
		return c, true
	}
	return pa.cmp(pb), true
}

// trimZeros0 is trimZeros that maps the empty string to "0".
func trimZeros0(d string) string {
	if d == "" {
		return "0"
	}
	return trimZeros(d)
}

// ── docker ──────────────────────────────────────────────────────────────────

// A tag is free text. Only a tag whose leading core is a numeric version is
// ordered; everything after the first hyphen is a flavour (alpine3.19, slim)
// that Renovate and the registries treat as an independent version line. A
// core with fewer than three fields (1.31, 3.12) is an alias that moves with
// every patch push.
type dockerAlgo struct{}

var (
	dockerTagRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	dockerCoreRe     = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})(?:(a|b|rc)(\d+))?(?:-(.+))?$`)
	dockerDateRe     = regexp.MustCompile(`^(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:\.\d+)?$`)
	dockerSnapshotRe = regexp.MustCompile(`^(?:sha-[0-9a-f]+|pr-\d+)$`)
	dockerAliasRe    = regexp.MustCompile(`^([A-Za-z]+)(\d+(?:\.\d+)*)$`)
	dockerNightlyRe  = regexp.MustCompile(`^nightly-\d{8}$`)
	dockerFlavour    = wordTable{
		"rc": {ReasonPrerelease}, "alpha": {ReasonPrerelease}, "beta": {ReasonPrerelease},
		"pre": {ReasonPrerelease}, "preview": {ReasonPrerelease}, "ea": {ReasonPrerelease},
		"dev": {ReasonDev}, "test": {ReasonDev}, "snapshot": {ReasonSnapshot},
		"nightly": {ReasonNightly}, "canary": {ReasonCanary},
		"edge": {ReasonEdge}, "unstable": {ReasonEdge},
	}
	dockerNumbered = map[string]bool{"rc": true, "alpha": true, "beta": true, "pre": true, "preview": true, "ea": true}
	dockerBranches = map[string]bool{"main": true, "master": true, "develop": true, "trunk": true}
)

func (dockerAlgo) classify(v string) (bool, bool, []string) {
	if strings.Contains(v, "sha256:") {
		return false, false, []string{ReasonDigest}
	}
	if !dockerTagRe.MatchString(v) {
		return unparseable()
	}
	if dockerSnapshotRe.MatchString(v) {
		return false, false, []string{ReasonSnapshot}
	}
	if m := dockerCoreRe.FindStringSubmatch(v); m != nil {
		var reasons []string
		if m[2] != "" {
			reasons = append(reasons, ReasonPrerelease)
		}
		orderable := true
		toks := tokens(m[4])
		for i, t := range toks {
			reasons = append(reasons, dockerFlavour[t]...)
			if dockerNumbered[t] && !(i+1 < len(toks) && isDigit(toks[i+1][0])) {
				// "3.16-rc-slim": a pre-release word with no number names no build.
				orderable = false
			}
		}
		if !dockerDateRe.MatchString(m[1]) && strings.Count(m[1], ".") < 2 {
			reasons = append(reasons, ReasonFloatingTag)
		}
		reasons = dedupe(reasons)
		if !orderable {
			return false, false, reasons
		}
		return verdict(reasons...)
	}
	if dockerNightlyRe.MatchString(v) {
		return verdict(ReasonNightly)
	}
	lv := strings.ToLower(v)
	reasons := dockerFlavour.reasons(lv)
	if dockerBranches[lv] {
		reasons = append(reasons, ReasonBranchRef)
	}
	return false, false, dedupe(append(reasons, ReasonFloatingTag))
}

type dockerTag struct {
	word    string // set for alpine3.19 style tags
	nums    []string
	pre     preKey
	flavour []string
}

func parseDockerTag(v string) (dockerTag, bool) {
	var t dockerTag
	if !dockerTagRe.MatchString(v) {
		return t, false
	}
	if m := dockerCoreRe.FindStringSubmatch(v); m != nil {
		t.nums, _ = dotNums(m[1])
		if m[2] != "" {
			t.pre = preKey{preRanks[m[2]], []string{trimZeros(m[3])}}
		}
		fl := tokens(m[4])
		if m[2] == "" && len(fl) > 0 && preRanks[fl[0]] < 0 {
			// "1.2.3-rc1" is a pre-release of 1.2.3, not a flavour.
			t.pre = parsePre(m[4])
			fl = nil
		}
		t.flavour = fl
		return t, true
	}
	if m := dockerAliasRe.FindStringSubmatch(v); m != nil {
		t.word = strings.ToLower(m[1])
		t.nums, _ = dotNums(m[2])
		return t, true
	}
	return t, false
}

func (dockerAlgo) compare(a, b string) (int, bool) {
	ta, oka := parseDockerTag(a)
	tb, okb := parseDockerTag(b)
	if !oka || !okb || ta.word != tb.word {
		return 0, false
	}
	if c := cmpTuple(ta.nums, tb.nums); c != 0 {
		return c, true
	}
	if c := ta.pre.cmp(tb.pre); c != 0 {
		return c, true
	}
	return cmpTokens(ta.flavour, tb.flavour), true
}

// ── git-ref ─────────────────────────────────────────────────────────────────

// A git ref has no version order. Tags that look like versions are ordered as
// SemVer; a `git describe` string (v1.2.3-5-g3f2a9c1) orders by tag then by the
// commit count since it, but is a development snapshot, not a release.
type gitRefAlgo struct{}

var (
	gitDescribeRe = regexp.MustCompile(`^(.+)-(\d+)-g[0-9a-f]{7,40}(-dirty)?$`)
	gitSemver     = semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 3, leadingZeros: true}}
	gitBranchWord = map[string]bool{"main": true, "master": true, "develop": true, "trunk": true, "dev": true, "next": true, "canary": true, "nightly": true, "head": true}
)

func (gitRefAlgo) classify(v string) (bool, bool, []string) {
	switch {
	case isDigest(v):
		return false, false, []string{ReasonDigest}
	case strings.HasSuffix(v, "^{}"):
		return unparseable()
	case strings.HasPrefix(v, "refs/tags/"):
		return gitClassifyTag(strings.TrimPrefix(v, "refs/tags/"))
	case strings.HasPrefix(v, "refs/heads/"):
		name := strings.TrimPrefix(v, "refs/heads/")
		if _, ok := gitSemver.parse(name); ok {
			return false, false, []string{ReasonBranchRef}
		}
		return false, false, []string{ReasonBranchRef, ReasonFloatingTag}
	case strings.HasPrefix(v, "refs/"):
		return false, false, []string{ReasonBranchRef}
	case gitBranchWord[strings.ToLower(v)]:
		return false, false, []string{ReasonBranchRef, ReasonFloatingTag}
	}
	return gitClassifyTag(v)
}

func gitClassifyTag(v string) (bool, bool, []string) {
	if gitDescribeRe.MatchString(v) {
		return false, false, []string{ReasonSnapshot}
	}
	if strings.HasSuffix(v, "-dirty") || strings.HasSuffix(v, ".dirty") {
		return false, false, []string{ReasonSnapshot}
	}
	return gitSemver.classify(v)
}

func gitKey(v string) (semverVer, int, bool) {
	v = strings.TrimPrefix(v, "refs/tags/")
	n := 0
	if m := gitDescribeRe.FindStringSubmatch(v); m != nil {
		v = m[1]
		n = atoiSmall(m[2])
	}
	p, ok := gitSemver.parse(v)
	return p, n, ok
}

// atoiSmall parses a commit count; an overflowing value saturates.
func atoiSmall(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return 1 << 30
		}
	}
	return n
}

func (gitRefAlgo) compare(a, b string) (int, bool) {
	pa, na, oka := gitKey(a)
	pb, nb, okb := gitKey(b)
	if !oka || !okb {
		return 0, false
	}
	if c := gitSemver.cmpVer(pa, pb); c != 0 {
		return c, true
	}
	return cmpInt(na, nb), true
}

// ── github-release ──────────────────────────────────────────────────────────

// A release tag is free text. Strip a repository prefix (cli-, release-,
// @scope/pkg@) and a v, then order the rest as SemVer, or as a date for
// release-2024-01. Never order by publish time: actions/checkout published
// v2.8.0 last on the day it published v7.0.1. A tag with under three fields
// (v4) is a floating major alias unless it carries a pre-release.
type githubAlgo struct{}

var (
	githubTagRe    = regexp.MustCompile(`^(?:[A-Za-z0-9_.@/-]*?[-_/@])?v?(\d+(?:\.\d+)*(?:[-+].*)?)$`)
	githubBareRe   = regexp.MustCompile(`^v?(\d+(?:\.\d+)*(?:[-+].*)?)$`)
	githubDateRe   = regexp.MustCompile(`^\d{4}-\d{2}(?:-\d{2})?$`)
	githubPseudoRe = regexp.MustCompile(`^\d{14}-[0-9a-f]{12}$`)
	githubSemver   = semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 1, maxParts: 4}}
	githubWords    = wordTable{"nightly": {ReasonNightly}, "canary": {ReasonCanary}, "dev": {ReasonDev}, "snapshot": {ReasonSnapshot}, "edge": {ReasonEdge}}
)

// githubMatch splits a tag into its prefix and version. The bare form is tried
// first so that v0.0.0-2024... is not read as a prefix "v0.0.0-" and a version.
func githubMatch(v string) []string {
	if m := githubBareRe.FindStringSubmatch(v); m != nil {
		return m
	}
	return githubTagRe.FindStringSubmatch(v)
}

func (githubAlgo) classify(v string) (bool, bool, []string) {
	if len(v) == 40 && isDigest(v) {
		return false, false, []string{ReasonDigest}
	}
	if m := githubMatch(v); m != nil {
		if githubDateRe.MatchString(m[1]) {
			return verdict(githubWords.reasons(v[:len(v)-len(m[1])])...)
		}
		p, ok := githubSemver.parse(m[1])
		if !ok {
			return unparseable()
		}
		switch {
		case p.hasP && githubPseudoRe.MatchString(strings.Join(p.pre, ".")):
			return verdict(ReasonSnapshot)
		case p.hasP:
			return verdict(dedupe(append([]string{ReasonPrerelease}, githubWords.reasons(strings.Join(p.pre, "."))...))...)
		case len(p.nums) < 3:
			return verdict(ReasonFloatingTag)
		}
		return verdict()
	}
	lv := strings.ToLower(v)
	var reasons []string
	switch lv {
	case "main", "master", "develop", "dev", "trunk", "head":
		reasons = []string{ReasonBranchRef}
	case "nightly", "continuous":
		reasons = []string{ReasonNightly}
	case "edge":
		reasons = []string{ReasonEdge}
	case "latest", "stable":
	default:
		return unparseable()
	}
	return false, false, append(reasons, ReasonFloatingTag)
}

func githubKey(v string) (kind int, date []string, p semverVer, ok bool) {
	m := githubMatch(v)
	if m == nil {
		return 0, nil, p, false
	}
	if githubDateRe.MatchString(m[1]) {
		for _, f := range strings.Split(m[1], "-") {
			date = append(date, trimZeros(f))
		}
		return 1, date, p, true
	}
	p, ok = githubSemver.parse(m[1])
	return 2, nil, p, ok
}

func (githubAlgo) compare(a, b string) (int, bool) {
	ka, da, pa, oka := githubKey(a)
	kb, db, pb, okb := githubKey(b)
	if !oka || !okb || ka != kb {
		return 0, false
	}
	if ka == 1 {
		return cmpTuple(da, db), true
	}
	return githubSemver.cmpVer(pa, pb), true
}

// ── go-toolchain ────────────────────────────────────────────────────────────

// Toolchain names are goX.Y[.Z][rcN|betaN]. Since Go 1.21 a bare goX.Y is the
// language version and sorts below its own release candidates
// (1.21 < 1.21rc1 < 1.21.0, go.dev/doc/toolchain); before 1.21 go1.20 was the
// first release itself. Module versions are SemVer with Go pseudo-versions.
type goToolchainAlgo struct{}

var (
	goToolRe   = regexp.MustCompile(`^(?:go)?(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?$`)
	goModule   = semverAlgo{semverOpts{vPrefix: "required", minParts: 1, maxParts: 3, goPseudo: true, buildStable: goBuildStable}}
	goBasePseu = regexp.MustCompile(`^v\d+\.0\.0-\d{14}-[0-9a-f]+`)
)

type goToolVer struct {
	major, minor string
	stage        int // 0 language version, 1 beta, 2 rc, 3 release
	n, patch     string
}

func parseGoTool(v string) (goToolVer, bool) {
	var t goToolVer
	m := goToolRe.FindStringSubmatch(v)
	if m == nil {
		return t, false
	}
	t.major, t.minor = trimZeros(m[1]), trimZeros(m[2])
	t.patch, t.n = "0", "0"
	switch {
	case m[4] == "beta":
		t.stage, t.n = 1, trimZeros(m[5])
	case m[4] == "rc":
		t.stage, t.n = 2, trimZeros(m[5])
	case m[3] != "":
		t.stage, t.patch = 3, trimZeros(m[3])
	case t.major == "1" && cmpDigits(t.minor, "21") < 0:
		t.stage = 3
	}
	return t, true
}

func (goToolchainAlgo) classify(v string) (bool, bool, []string) {
	switch {
	case v == "gotip":
		return false, false, []string{ReasonFloatingTag, ReasonDev}
	case strings.HasPrefix(v, "devel "):
		return false, false, []string{ReasonDev}
	}
	if t, ok := parseGoTool(v); ok {
		switch t.stage {
		case 0:
			return false, false, []string{ReasonFloatingTag}
		case 1, 2:
			return verdict(ReasonPrerelease)
		}
		return verdict()
	}
	if !goModule.o.goPseudo || !goPseudoR.MatchString(v) {
		return goModule.classify(v)
	}
	if goBasePseu.MatchString(v) {
		return verdict(ReasonSnapshot)
	}
	return verdict(ReasonSnapshot, ReasonPrerelease)
}

func (goToolchainAlgo) compare(a, b string) (int, bool) {
	ta, oka := parseGoTool(a)
	tb, okb := parseGoTool(b)
	if oka && okb {
		for _, c := range []int{
			cmpDigits(ta.major, tb.major), cmpDigits(ta.minor, tb.minor),
			cmpInt(ta.stage, tb.stage), cmpDigits(ta.n, tb.n), cmpDigits(ta.patch, tb.patch),
		} {
			if c != 0 {
				return c, true
			}
		}
		return 0, true
	}
	if oka || okb {
		return 0, false
	}
	return goModule.compare(a, b)
}

// ── java ────────────────────────────────────────────────────────────────────

// JEP 223: $VNUM(-$PRE)?(+$BUILD)?(-$OPT)?. A PRE sorts below the bare VNUM and
// BUILD counts (17.0.9+9 < 17.0.9+10), unlike SemVer build metadata. The legacy
// 1.8.0_392-b08 and 8u392-b08 forms are folded into the same tuple.
type javaAlgo struct{}

var (
	javaRe      = regexp.MustCompile(`^(\d+(?:\.\d+)*)(?:-([A-Za-z0-9]+))?(?:\+(\d+))?(?:-([A-Za-z0-9._-]+))?$`)
	javaLegacy1 = regexp.MustCompile(`^1\.(\d+)\.(\d+)_(\d+)(?:-b(\d+))?$`)
	javaLegacy2 = regexp.MustCompile(`^(\d+)u(\d+)(?:-b(\d+))?$`)
)

type javaVer struct {
	nums     []string
	pre      string
	hasPre   bool
	build    string
	hasBuild bool
}

func parseJava(v string) (javaVer, bool) {
	var j javaVer
	if m := javaLegacy1.FindStringSubmatch(v); m != nil {
		j.nums = []string{trimZeros(m[1]), trimZeros(m[2]), trimZeros(m[3])}
		j.build, j.hasBuild = m[4], m[4] != ""
		return j, true
	}
	if m := javaLegacy2.FindStringSubmatch(v); m != nil {
		j.nums = []string{trimZeros(m[1]), "0", trimZeros(m[2])}
		j.build, j.hasBuild = m[3], m[3] != ""
		return j, true
	}
	m := javaRe.FindStringSubmatch(v)
	if m == nil {
		return j, false
	}
	j.nums, _ = dotNums(m[1])
	j.pre, j.hasPre = m[2], m[2] != ""
	j.build, j.hasBuild = m[3], m[3] != ""
	return j, true
}

func (javaAlgo) classify(v string) (bool, bool, []string) {
	if v == "lts" {
		return false, false, []string{ReasonFloatingTag}
	}
	j, ok := parseJava(v)
	if !ok {
		return unparseable()
	}
	if !j.hasPre {
		return verdict()
	}
	switch strings.ToLower(j.pre) {
	case "internal", "snapshot", "adhoc":
		return verdict(ReasonSnapshot)
	}
	return verdict(ReasonPrerelease)
}

func (javaAlgo) compare(a, b string) (int, bool) {
	ja, oka := parseJava(a)
	jb, okb := parseJava(b)
	if !oka || !okb {
		return 0, false
	}
	if c := cmpTuple(ja.nums, jb.nums); c != 0 {
		return c, true
	}
	switch {
	case ja.hasPre && !jb.hasPre:
		return -1, true
	case !ja.hasPre && jb.hasPre:
		return 1, true
	case ja.hasPre:
		if c := cmpTokens(tokens(ja.pre), tokens(jb.pre)); c != 0 {
			return c, true
		}
	}
	switch {
	case ja.hasBuild && jb.hasBuild:
		return cmpDigits(trimZeros(ja.build), trimZeros(jb.build)), true
	case ja.hasBuild:
		return 1, true
	case jb.hasBuild:
		return -1, true
	}
	return 0, true
}

// ── letter-suffix ───────────────────────────────────────────────────────────

// SQLite, zlib, libpng, curl and bash: a dotted tuple (or sqlite's integer
// X*1000000+Y*1000+Z) with a suffix that is either a pre-release glued to the
// next number (libpng 1.6.44beta01, bash 5.3-rc1) or a development marker
// (zlib 1.2.11.f, -motley). A leading project name is not part of the version.
type letterSuffixAlgo struct{}

var (
	lsNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*[ -]`)
	lsRCRe   = regexp.MustCompile(`^rc-(\d+(?:_\d+)*)(?:-(\d+))?$`)
	lsRe     = regexp.MustCompile(`^(\d+(?:[._]\d+)*)(?:\.([a-z]))?(?:-?(alpha|beta|rc)(\d*))?(?:\(\d+\))?(?:-(release|motley))?$`)
)

type lsVer struct {
	nums    []string
	pre     preKey
	reasons []string
}

func parseLetterSuffix(v string) (lsVer, bool) {
	var out lsVer
	v = strings.TrimSpace(v)
	if strings.Contains(strings.ToLower(v), "snapshot") {
		return out, false
	}
	if m := lsRCRe.FindStringSubmatch(v); m != nil {
		out.nums, _ = dotNums(strings.ReplaceAll(m[1], "_", "."))
		out.pre = preKey{preRanks["rc"], []string{trimZeros0(m[2])}}
		out.reasons = []string{ReasonPrerelease}
		return out, true
	}
	v = lsNameRe.ReplaceAllString(v, "")
	m := lsRe.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	core := strings.ReplaceAll(m[1], "_", ".")
	if digitsRe.MatchString(core) && len(core) >= 7 {
		// sqlite_libversion_number: X*1000000 + Y*1000 + Z.
		n := len(core)
		core = core[:n-6] + "." + core[n-6:n-3] + "." + core[n-3:]
	}
	out.nums, _ = dotNums(core)
	switch {
	case m[3] != "":
		out.pre = preKey{preRanks[m[3]], []string{trimZeros0(m[4])}}
		out.reasons = []string{ReasonPrerelease}
	case m[2] != "":
		out.pre = preKey{preRanks["dev"], []string{m[2]}}
		out.reasons = []string{ReasonDev}
	}
	if m[5] == "motley" {
		out.pre = preKey{preRanks["dev"], []string{"motley"}}
		out.reasons = append(out.reasons, ReasonDev, ReasonBuildMetadata)
	}
	return out, true
}

func (letterSuffixAlgo) classify(v string) (bool, bool, []string) {
	if strings.Contains(strings.ToLower(v), "snapshot") {
		return false, false, []string{ReasonSnapshot}
	}
	p, ok := parseLetterSuffix(v)
	if !ok {
		return unparseable()
	}
	return verdict(dedupe(p.reasons)...)
}

func (letterSuffixAlgo) compare(a, b string) (int, bool) {
	pa, oka := parseLetterSuffix(a)
	pb, okb := parseLetterSuffix(b)
	if !oka || !okb {
		return 0, false
	}
	if c := cmpTuple(pa.nums, pb.nums); c != 0 {
		return c, true
	}
	return pa.pre.cmp(pb.pre), true
}

// ── linux-kernel and linux ──────────────────────────────────────────────────

// kernelAlgo is the release-tracking view of the kernel: X.Y mainline, X.Y.Z
// stable and longterm, X.Y-rcN candidates and next-YYYYMMDD integration
// snapshots. Distribution suffixes (-generic, -rt70) are build metadata. Before
// 2.6 an odd minor was a development series.
type kernelAlgo struct{}

var kernelRe = regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3})(?:-rc(\d+))?([-+].+)?$`)

type kernelVer struct {
	nums []string
	rc   preKey
	next string
	rest string
}

func parseKernel(v string, allowRest bool) (kernelVer, bool) {
	var k kernelVer
	if strings.HasPrefix(v, "next-") && len(v) == 13 && digitsRe.MatchString(v[5:]) {
		k.next = v[5:]
		return k, true
	}
	m := kernelRe.FindStringSubmatch(v)
	if m == nil || (m[3] != "" && !allowRest) {
		return k, false
	}
	k.nums, _ = dotNums(m[1])
	if m[2] != "" {
		k.rc = preKey{preRanks["rc"], []string{trimZeros(m[2])}}
	}
	k.rest = m[3]
	return k, true
}

func (k kernelVer) cmp(o kernelVer) (int, bool) {
	if k.next != "" || o.next != "" {
		if k.next != "" && o.next != "" {
			return strings.Compare(k.next, o.next), true
		}
		return 0, false
	}
	if c := cmpTuple(k.nums, o.nums); c != 0 {
		return c, true
	}
	return k.rc.cmp(o.rc), true
}

func (kernelAlgo) classify(v string) (bool, bool, []string) {
	k, ok := parseKernel(v, true)
	if !ok {
		return unparseable()
	}
	if k.next != "" {
		return verdict(ReasonNightly, ReasonSnapshot)
	}
	var reasons []string
	if k.rc.rank != 0 {
		reasons = append(reasons, ReasonPrerelease)
	}
	if strings.Contains(k.rest, "dirty") {
		reasons = append(reasons, ReasonSnapshot)
	}
	if len(k.nums) >= 2 && cmpDigits(k.nums[0], "2") <= 0 && (k.nums[1][len(k.nums[1])-1]-'0')%2 == 1 {
		reasons = append(reasons, ReasonOddMinor)
	}
	return verdict(reasons...)
}

func (kernelAlgo) compare(a, b string) (int, bool) {
	ka, oka := parseKernel(a, true)
	kb, okb := parseKernel(b, true)
	if !oka || !okb {
		return 0, false
	}
	return ka.cmp(kb)
}

// linuxAlgo is the OSV Linux ecosystem: kernel.org version numbers only, so a
// distribution suffix or a single field is not a version.
type linuxAlgo struct{}

func (linuxAlgo) classify(v string) (bool, bool, []string) {
	k, ok := parseKernel(v, false)
	if !ok {
		return unparseable()
	}
	switch {
	case k.next != "":
		return verdict(ReasonDev)
	case k.rc.rank != 0:
		return verdict(ReasonPrerelease)
	}
	return verdict()
}

func (linuxAlgo) compare(a, b string) (int, bool) {
	ka, oka := parseKernel(a, false)
	kb, okb := parseKernel(b, false)
	if !oka || !okb {
		return 0, false
	}
	return ka.cmp(kb)
}

// ── npm dist-tags ───────────────────────────────────────────────────────────

var npmWords = wordTable{
	"canary": {ReasonCanary}, "experimental": {ReasonCanary, ReasonPrerelease},
	"dev": {ReasonDev}, "nightly": {ReasonNightly}, "snapshot": {ReasonSnapshot},
	"insiders": {ReasonPrerelease}, "preview": {ReasonPrerelease}, "beta": {ReasonPrerelease},
	"alpha": {ReasonPrerelease}, "rc": {ReasonPrerelease}, "next": {ReasonPrerelease}, "pre": {ReasonPrerelease},
}

// npmPreReasons names the channel in a pre-release. React's canary and
// experimental builds embed a hash and a date inside one identifier
// (19.3.0-canary-9ffcb463-20261021), so only a date that stands alone as an
// identifier (dev.20261022.1, insiders.20220225) marks a nightly.
func npmPreReasons(p semverVer) []string {
	return preWords(p, npmWords, true)
}

// npmTagName judges a dist-tag. Tags that look like a version or range are
// rejected by npm, so they are not tags.
func npmTagName(v string) (bool, bool, []string) {
	if !nameRe.MatchString(v) || strings.HasPrefix(v, "v") && len(v) > 1 && isDigit(v[1]) {
		return unparseable()
	}
	return false, false, dedupe(append(npmWords.reasons(v), ReasonFloatingTag))
}

// ── openssl ─────────────────────────────────────────────────────────────────

// OpenSSL up to 1.1.1 uses trailing letters as a post-release counter
// (1.1.1 < 1.1.1a < 1.1.1z < 1.1.1za, ordered by length then letters); from 3.0
// it is SemVer with -alphaN/-betaN. Git tags (openssl-3.5.9, OpenSSL_1_1_1w)
// carry the same version, and a distribution suffix (-fips) is build metadata.
type opensslAlgo struct{}

var opensslRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)([a-z]*)(?:-(alpha|beta|pre|dev)(\d*)|-(.+))?$`)

type opensslVer struct {
	nums    []string
	letters string
	pre     preKey
}

func parseOpenssl(v string) (opensslVer, string, bool) {
	var o opensslVer
	switch {
	case strings.HasPrefix(v, "openssl-"):
		v = v[len("openssl-"):]
	case strings.HasPrefix(v, "OpenSSL_"):
		v = strings.ReplaceAll(v[len("OpenSSL_"):], "_", ".")
	}
	m := opensslRe.FindStringSubmatch(v)
	if m == nil {
		return o, "", false
	}
	o.nums = []string{trimZeros(m[1]), trimZeros(m[2]), trimZeros(m[3])}
	o.letters = m[4]
	if m[5] != "" {
		o.pre = preKey{preRanks[m[5]], []string{trimZeros0(m[6])}}
	}
	return o, m[5], true
}

func (opensslAlgo) classify(v string) (bool, bool, []string) {
	_, word, ok := parseOpenssl(v)
	if !ok {
		return unparseable()
	}
	switch word {
	case "":
		return verdict()
	case "dev":
		return verdict(ReasonDev)
	}
	return verdict(ReasonPrerelease)
}

func (opensslAlgo) compare(a, b string) (int, bool) {
	oa, _, oka := parseOpenssl(a)
	ob, _, okb := parseOpenssl(b)
	if !oka || !okb {
		return 0, false
	}
	if c := cmpTuple(oa.nums, ob.nums); c != 0 {
		return c, true
	}
	if c := oa.pre.cmp(ob.pre); c != 0 {
		return c, true
	}
	if len(oa.letters) != len(ob.letters) {
		return cmpInt(len(oa.letters), len(ob.letters)), true
	}
	return strings.Compare(oa.letters, ob.letters), true
}

// ── php ─────────────────────────────────────────────────────────────────────

// version_compare() canonicalises the string (_ - + become dots, a dot goes
// between digits and letters) and ranks special words:
// dev < alpha=a < beta=b < RC=rc < number < pl=p. Composer branches (dev-main,
// 8.x-dev) are refs, not versions.
type phpAlgo struct{}

var phpForms = []struct {
	name  string
	order int
}{{"dev", 0}, {"alpha", 1}, {"a", 1}, {"beta", 2}, {"b", 2}, {"RC", 3}, {"rc", 3}, {"#", 4}, {"pl", 5}, {"p", 5}}

func phpCanon(v string) []string {
	if v == "" {
		return nil
	}
	isNDig := func(c byte) bool { return !isDigit(c) && c != '.' }
	b := []byte{v[0]}
	lp := v[0]
	for i := 1; i < len(v); i++ {
		c := v[i]
		lq := b[len(b)-1]
		switch {
		case c == '-' || c == '_' || c == '+':
			if lq != '.' {
				b = append(b, '.')
			}
		case (isNDig(lp) && isDigit(c)) || (isDigit(lp) && isNDig(c)):
			if lq != '.' {
				b = append(b, '.')
			}
			b = append(b, c)
		case !isDigit(c) && !isAlpha(c):
			if lq != '.' {
				b = append(b, '.')
			}
		default:
			b = append(b, c)
		}
		lp = c
	}
	return strings.Split(string(b), ".")
}

func phpSpecial(s string) int {
	for _, f := range phpForms {
		if strings.HasPrefix(s, f.name) {
			return f.order
		}
	}
	return -1
}

func phpCmpParts(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		var c int
		switch xd, yd := x != "" && isDigit(x[0]), y != "" && isDigit(y[0]); {
		case xd && yd:
			c = cmpDigits(trimZeros0(x), trimZeros0(y))
		case !xd && !yd:
			c = cmpInt(phpSpecial(x), phpSpecial(y))
		case xd:
			c = cmpInt(phpSpecial("#"), phpSpecial(y))
		default:
			c = cmpInt(phpSpecial(x), phpSpecial("#"))
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(a) > len(b):
		if isDigit(a[len(b)][0]) {
			return 1
		}
		return cmpInt(phpSpecial(a[len(b)]), phpSpecial("#"))
	case len(b) > len(a):
		if isDigit(b[len(a)][0]) {
			return -1
		}
		return cmpInt(phpSpecial("#"), phpSpecial(b[len(a)]))
	}
	return 0
}

var phpRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)[-_.]?([A-Za-z]*)\d*`)

func phpStrip(v string) string { return strings.TrimPrefix(v, "php-") }

func (phpAlgo) classify(v string) (bool, bool, []string) {
	v = phpStrip(v)
	if strings.HasPrefix(v, "dev-") {
		return false, false, []string{ReasonBranchRef}
	}
	if strings.HasSuffix(v, "-dev") && strings.ContainsAny(v, "xX*") {
		return false, false, []string{ReasonDev, ReasonBranchRef}
	}
	m := phpRe.FindStringSubmatch(v)
	if m == nil {
		return unparseable()
	}
	switch m[2] {
	case "alpha", "a", "beta", "b", "RC", "rc":
		return verdict(ReasonPrerelease)
	case "dev":
		return verdict(ReasonDev)
	}
	return verdict()
}

func (phpAlgo) compare(a, b string) (int, bool) {
	a, b = phpStrip(a), phpStrip(b)
	if !phpRe.MatchString(a) || !phpRe.MatchString(b) {
		return 0, false
	}
	return phpCmpParts(phpCanon(a), phpCanon(b)), true
}

// ── python-runtime ──────────────────────────────────────────────────────────

// CPython versions follow PEP 440. A two-field 3.12 is the minor-line alias,
// pyenv's 3.14-dev is a moving development build, a trailing + marks a build
// from a modified checkout, and PyPy has its own numbering.
type pythonRuntimeAlgo struct{}

var pyLineRe = regexp.MustCompile(`^\d+\.\d+$`)

func (pythonRuntimeAlgo) classify(v string) (bool, bool, []string) {
	switch {
	case strings.HasPrefix(v, "pypy"):
		return false, true, nil
	case strings.HasSuffix(v, "-dev"):
		return false, false, []string{ReasonDev, ReasonFloatingTag}
	}
	var reasons []string
	if strings.HasSuffix(v, "+") {
		v = strings.TrimSuffix(v, "+")
		reasons = append(reasons, ReasonSnapshot)
	}
	orderable, _, more := pep440Algo{}.classify(v)
	if !orderable {
		return unparseable()
	}
	if pyLineRe.MatchString(v) {
		more = append(more, ReasonFloatingTag)
	}
	return verdict(dedupe(append(reasons, more...))...)
}

func (pythonRuntimeAlgo) compare(a, b string) (int, bool) {
	return comparePEP440(strings.TrimSuffix(a, "+"), strings.TrimSuffix(b, "+"))
}

// ── rust-toolchain ──────────────────────────────────────────────────────────

// Releases are SemVer (1.99.1, 1.100.0-beta.7). The channels stable, beta and
// nightly are moving pointers, and a dated toolchain (nightly-2026-10-22) is
// ordered by its date because every nightly of a cycle shares one version.
type rustAlgo struct{}

var (
	rustChannelRe = regexp.MustCompile(`^(stable|beta|nightly)(?:-(\d{4})-(\d{2})-(\d{2}))?(?:-([a-z0-9_]+(?:-[a-z0-9_]+)+))?$`)
	rustcOutRe    = regexp.MustCompile(`^rustc \d+\.\d+\.\d+(?:-[a-z.0-9]+)?(?: \(.*\))?$`)
	rustSemver    = semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 2, maxParts: 3, leadingZeros: true}}
)

func (rustAlgo) classify(v string) (bool, bool, []string) {
	if m := rustChannelRe.FindStringSubmatch(v); m != nil {
		dated := m[2] != ""
		switch {
		case m[1] == "stable" && dated:
			return verdict()
		case m[1] == "stable":
			return false, false, []string{ReasonFloatingTag}
		case m[1] == "beta" && dated:
			return verdict(ReasonPrerelease)
		case m[1] == "beta":
			return false, false, []string{ReasonFloatingTag, ReasonPrerelease}
		case dated:
			return verdict(ReasonNightly)
		}
		return false, false, []string{ReasonFloatingTag, ReasonNightly}
	}
	if rustcOutRe.MatchString(v) {
		if strings.Contains(v, "-nightly") || strings.Contains(v, "-dev") {
			return false, false, []string{ReasonNightly}
		}
		return false, false, []string{ReasonPrerelease}
	}
	p, ok := rustSemver.parse(v)
	if !ok {
		return unparseable()
	}
	switch {
	case p.hasP:
		return verdict(dedupe(preWords(p, wordTable{"nightly": {ReasonNightly}, "dev": {ReasonDev}}, false))...)
	case len(p.nums) < 3:
		return verdict(ReasonFloatingTag)
	}
	return verdict()
}

func (rustAlgo) compare(a, b string) (int, bool) {
	ma, mb := rustChannelRe.FindStringSubmatch(a), rustChannelRe.FindStringSubmatch(b)
	if ma != nil || mb != nil {
		if ma == nil || mb == nil || ma[1] != mb[1] || ma[2] == "" || mb[2] == "" {
			return 0, false
		}
		return strings.Compare(ma[2]+ma[3]+ma[4], mb[2]+mb[3]+mb[4]), true
	}
	return rustSemver.compare(a, b)
}

// ── scoop ───────────────────────────────────────────────────────────────────

// Scoop's Compare-Version (lib/versions.ps1) rewrites + to -, so a + suffix is a
// post-release, splits letters from digits, and ranks alpha/beta/rc/pre below
// the bare number. Two bare "nightly" versions compare equal, so nightly can
// only be ordered by a trailing date.
type scoopAlgo struct{}

var (
	scoopRe        = regexp.MustCompile(`^\d[0-9A-Za-z._+-]*$`)
	scoopNightlyRe = regexp.MustCompile(`^nightly-(\d{8})$`)
	scoopPreRe     = regexp.MustCompile(`alpha|beta|rc|pre`)
	scoopWords     = wordTable{
		"alpha": {ReasonPrerelease}, "beta": {ReasonPrerelease}, "rc": {ReasonPrerelease}, "pre": {ReasonPrerelease},
		"dev": {ReasonDev}, "snapshot": {ReasonSnapshot}, "canary": {ReasonCanary}, "nightly": {ReasonNightly},
	}
)

func (scoopAlgo) classify(v string) (bool, bool, []string) {
	lv := strings.ToLower(v)
	switch {
	case lv == "nightly":
		return false, false, []string{ReasonNightly, ReasonFloatingTag}
	case scoopNightlyRe.MatchString(lv):
		return verdict(ReasonNightly)
	case !scoopRe.MatchString(v):
		return unparseable()
	}
	if i := strings.IndexByte(lv, '+'); i >= 0 {
		lv = lv[:i]
	}
	return verdict(scoopWords.reasons(lv)...)
}

func (scoopAlgo) compare(a, b string) (int, bool) {
	a, b = strings.ToLower(a), strings.ToLower(b)
	ma, mb := scoopNightlyRe.FindStringSubmatch(a), scoopNightlyRe.FindStringSubmatch(b)
	if ma != nil || mb != nil || a == "nightly" || b == "nightly" {
		if ma == nil || mb == nil {
			return 0, false
		}
		return strings.Compare(ma[1], mb[1]), true
	}
	if !scoopRe.MatchString(a) || !scoopRe.MatchString(b) {
		return 0, false
	}
	ta, tb := tokens(strings.ReplaceAll(a, "+", "-")), tokens(strings.ReplaceAll(b, "+", "-"))
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			if scoopPreRe.MatchString(tb[i]) {
				return 1, true
			}
			return -1, true
		case i >= len(tb):
			if scoopPreRe.MatchString(ta[i]) {
				return -1, true
			}
			return 1, true
		}
		x, y := ta[i], tb[i]
		xd, yd := isDigit(x[0]), isDigit(y[0])
		switch {
		case xd && yd:
			if c := cmpDigits(trimZeros(x), trimZeros(y)); c != 0 {
				return c, true
			}
		case xd:
			if scoopPreRe.MatchString(y) {
				return 1, true
			}
			return -1, true
		case yd:
			if scoopPreRe.MatchString(x) {
				return -1, true
			}
			return 1, true
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c, true
			}
		}
	}
	return 0, true
}

// ── ubuntu ──────────────────────────────────────────────────────────────────

// YY.MM with an optional .N point release (22.04.5). An image suffix is either
// a pre-release (-beta), a daily build, or the build date of a rebuild
// (24.04-20241001). Codenames and rolling/devel/latest are moving pointers.
type ubuntuAlgo struct{}

var ubuntuRe = regexp.MustCompile(`^(\d{2})\.(0[1-9]|1[0-2])(?:\.(\d+))?(?:-(beta|alpha|daily|\d{8}))?$`)

func (ubuntuAlgo) classify(v string) (bool, bool, []string) {
	if m := ubuntuRe.FindStringSubmatch(v); m != nil {
		switch m[4] {
		case "":
			return verdict()
		case "beta", "alpha":
			return verdict(ReasonPrerelease)
		case "daily":
			return false, false, []string{ReasonNightly}
		}
		return verdict()
	}
	if v == "devel" {
		return false, false, []string{ReasonFloatingTag, ReasonDev}
	}
	if regexp.MustCompile(`^[a-z]+$`).MatchString(v) {
		return false, false, []string{ReasonFloatingTag}
	}
	return unparseable()
}

func (ubuntuAlgo) compare(a, b string) (int, bool) {
	ma, mb := ubuntuRe.FindStringSubmatch(a), ubuntuRe.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[4] == "daily" || mb[4] == "daily" {
		return 0, false
	}
	key := func(m []string) ([]string, preKey) {
		pre := preKey{}
		if m[4] == "alpha" || m[4] == "beta" {
			pre = preKey{preRanks[m[4]], nil}
		} else if m[4] != "" {
			pre = preKey{1, []string{m[4]}}
		}
		return []string{trimZeros(m[1]), trimZeros(m[2]), trimZeros0(m[3])}, pre
	}
	na, pa := key(ma)
	nb, pb := key(mb)
	if c := cmpTuple(na, nb); c != 0 {
		return c, true
	}
	return pa.cmp(pb), true
}

// ── unity ───────────────────────────────────────────────────────────────────

// Unity: year.minor.patch + stream letter + index (2022.3.10f1). The stream
// orders a < b < f < p. A trailing c1 (China build) or "(hash)" is not ordered.
// Without the stream letter (2022.3) the string names a release line.
type unityAlgo struct{}

var unityRe = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+)([abfp])(\d+)(?:c\d+)?(?: \([0-9a-f]+\))?)?$`)

func (unityAlgo) classify(v string) (bool, bool, []string) {
	m := unityRe.FindStringSubmatch(v)
	switch {
	case m == nil:
		return unparseable()
	case m[3] == "":
		return verdict(ReasonFloatingTag)
	case m[4] == "a" || m[4] == "b":
		return verdict(ReasonPrerelease)
	}
	return verdict()
}

func (unityAlgo) compare(a, b string) (int, bool) {
	ma, mb := unityRe.FindStringSubmatch(a), unityRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	stream := map[string]string{"": "0", "a": "1", "b": "2", "f": "3", "p": "4"}
	key := func(m []string) []string {
		patch := "0"
		if m[3] != "" {
			patch = trimZeros(m[3])
		}
		return []string{trimZeros(m[1]), trimZeros(m[2]), patch, stream[m[4]], trimZeros0(m[5])}
	}
	return cmpTuple(key(ma), key(mb)), true
}

// ── vscode ──────────────────────────────────────────────────────────────────

var vscodeStampRe = regexp.MustCompile(`^20\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d\d$`)

// vscodeReasons applies what the version string can say. The Marketplace flag
// is authoritative but not in the string: nightly pre-releases carry a date
// stamped patch (2026.11.2026102101), and the recommended parity (odd minor =
// pre-release) is a hint that pre-2022 releases with a build-id patch break.
func vscodeReasons(p semverVer) []string {
	if p.hasP {
		// Open VSX lists some semver suffixes (2024.23.0-dev) the Marketplace rejects.
		return append([]string{ReasonPrerelease}, preWords(p, wordTable{"dev": {ReasonDev}, "nightly": {ReasonNightly}, "snapshot": {ReasonSnapshot}}, false)...)
	}
	odd := (p.nums[1][len(p.nums[1])-1]-'0')%2 == 1
	switch {
	case vscodeStampRe.MatchString(p.nums[2]):
		if odd {
			return []string{ReasonPrerelease, ReasonOddMinor}
		}
		return []string{ReasonPrerelease}
	case odd && len(p.nums[2]) < 10:
		return []string{ReasonOddMinor}
	}
	return nil
}

// ── windows-version ─────────────────────────────────────────────────────────

// A Windows file version is four 16-bit integers. An MSI ProductVersion of up
// to three fields is tighter: major and minor at most 255. A FileVersion string
// that is free text (5.00.RC2) names a pre-release but cannot be ordered.
type windowsAlgo struct{}

var windowsPreRe = regexp.MustCompile(`(?i)^\d+(?:\.\d+)*\.(?:rc|beta|preview)\d*$`)

func parseWindows(v string) ([]string, bool) {
	nums, ok := dotNums(v)
	if !ok || len(nums) > 4 {
		return nil, false
	}
	for i, n := range nums {
		limit := "65535"
		if len(nums) <= 3 && i < 2 {
			limit = "255"
		}
		if cmpDigits(n, limit) > 0 {
			return nil, false
		}
	}
	return nums, true
}

func (windowsAlgo) classify(v string) (bool, bool, []string) {
	if windowsPreRe.MatchString(v) {
		return false, false, []string{ReasonPrerelease}
	}
	if _, ok := parseWindows(v); !ok {
		return unparseable()
	}
	return verdict()
}

func (windowsAlgo) compare(a, b string) (int, bool) {
	na, oka := parseWindows(a)
	nb, okb := parseWindows(b)
	if !oka || !okb {
		return 0, false
	}
	return cmpTuple(na, nb), true
}

// ── winget ──────────────────────────────────────────────────────────────────

// winget-cli Versions.cpp: trim a leading non-digit prefix, split on dots, and
// read each part as an integer plus trailing text. Trailing zero parts are
// dropped; with equal integers an empty tail sorts above a non-empty one, so
// 1.2.3-beta and 1.2.3+build5 both sort below 1.2.3.
type wingetAlgo struct{}

var (
	wingetRe    = regexp.MustCompile(`^[A-Za-z]*(\d[0-9A-Za-z._+-]*)$`)
	wingetWords = wordTable{
		"nightly": {ReasonNightly}, "dev": {ReasonDev}, "snapshot": {ReasonSnapshot}, "canary": {ReasonCanary},
		"alpha": {ReasonPrerelease}, "beta": {ReasonPrerelease}, "rc": {ReasonPrerelease}, "pre": {ReasonPrerelease},
		"preview": {ReasonPrerelease}, "insider": {ReasonPrerelease}, "insiders": {ReasonPrerelease},
	}
)

type wingetPart struct{ n, other string }

func parseWinget(v string) ([]wingetPart, bool) {
	m := wingetRe.FindStringSubmatch(v)
	if m == nil {
		return nil, false
	}
	var parts []wingetPart
	for _, s := range strings.Split(m[1], ".") {
		i := 0
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		parts = append(parts, wingetPart{trimZeros0(s[:i]), strings.ToLower(s[i:])})
	}
	for len(parts) > 1 && parts[len(parts)-1].n == "0" && parts[len(parts)-1].other == "" {
		parts = parts[:len(parts)-1]
	}
	return parts, true
}

func (wingetAlgo) classify(v string) (bool, bool, []string) {
	if strings.EqualFold(v, "latest") {
		return false, false, []string{ReasonFloatingTag}
	}
	if _, ok := parseWinget(v); !ok {
		return unparseable()
	}
	lv := v
	if i := strings.IndexByte(lv, '+'); i >= 0 {
		lv = lv[:i]
	}
	return verdict(wingetWords.reasons(lv)...)
}

func (wingetAlgo) compare(a, b string) (int, bool) {
	pa, oka := parseWinget(a)
	pb, okb := parseWinget(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := wingetPart{"0", ""}, wingetPart{"0", ""}
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := cmpDigits(x.n, y.n); c != 0 {
			return c, true
		}
		switch {
		case x.other == y.other:
		case x.other == "":
			return 1, true
		case y.other == "":
			return -1, true
		default:
			return strings.Compare(x.other, y.other), true
		}
	}
	return 0, true
}

// ── android ─────────────────────────────────────────────────────────────────

// OSV's Android ecosystem names a platform branch with an optional security
// patch level: 14, 12L, 16-qpr2, 8.1, and 14:2024-03-01. No reference comparator
// exists; the order is platform number, then L, then QPR number, then the
// patch level ("0" meaning since the start). A -next branch is the unreleased
// development track and is only comparable with its own kind.
type androidAlgo struct{}

var androidRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)(L)?(?:-qpr(\d+))?(-next)?(?::(0|\d{4}-\d{2}-\d{2}))?$`)

func (androidAlgo) classify(v string) (bool, bool, []string) {
	m := androidRe.FindStringSubmatch(v)
	if m == nil {
		return unparseable()
	}
	if m[4] != "" {
		return verdict(ReasonDev)
	}
	return verdict()
}

func (androidAlgo) compare(a, b string) (int, bool) {
	ma, mb := androidRe.FindStringSubmatch(a), androidRe.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[4] != mb[4] {
		return 0, false
	}
	key := func(m []string) []string {
		plat, _ := dotNums(m[1])
		l := "0"
		if m[2] != "" {
			l = "1"
		}
		spl := []string{"0", "0", "0"}
		if m[5] != "" && m[5] != "0" {
			spl = nil
			for _, f := range strings.Split(m[5], "-") {
				spl = append(spl, trimZeros(f))
			}
		}
		return append(append(plat, "0", l, trimZeros0(m[3])), spl...)
	}
	ka, kb := key(ma), key(mb)
	// Align the variable-length platform number before the fixed tail.
	pa, pb := len(ka)-6, len(kb)-6
	if c := cmpTuple(ka[:pa], kb[:pb]); c != 0 {
		return c, true
	}
	return cmpTuple(ka[pa:], kb[pb:]), true
}
