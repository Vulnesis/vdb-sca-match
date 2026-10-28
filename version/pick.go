package version

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Candidate is one release of a package. The caller has already removed every
// release reported as malware: no outcome may ever be drawn from one.
type Candidate struct {
	Version string
	// PublishedAtMs is the release time in Unix milliseconds, nil when unknown.
	PublishedAtMs *int64
	// Exposed marks a release with a known vulnerability, exploit or end of
	// life. It is left out of latest, safest and stable, which are drawn from
	// clean releases only, and kept for rolling, which is the most recent
	// release day whatever its exposure.
	Exposed bool
}

// Picks is the safe harbour outcome for one package.
type Picks struct {
	// Scheme is the catalogue id the package's versions were judged under.
	Scheme string
	// Orderable is true when the scheme could order the package's versions, so
	// Latest and Safest are the highest release and not the most recent one.
	Orderable bool
	// Latest is the highest stable release. For a package whose versions no
	// scheme can order, it is the most recently published stable release.
	Latest string
	// Safest is the highest stable release. It is computed apart from Latest so
	// the two definitions can diverge, but today they agree.
	Safest string
	// Stable is the stable release closest to the running version.
	Stable string
	// Parity is the available release nearest to the running version by the
	// scheme's full order: the lowest at or above it, else the highest below.
	// It keeps behaviour as close to what runs today as the candidates allow,
	// so exposed releases are eligible; it is not a safety pick.
	Parity string
	// Rolling is every distinct non-malware version published on the release
	// date of the highest version (the most recent date when the package cannot
	// be ordered), pre-releases and exposed releases included, highest first. It
	// is the safer rolling: the freshest release day with malware removed, found
	// by version order and then date as latest is, so neither a malicious upload
	// nor a back-port to an old branch sets the day.
	Rolling []string
	// RollingDate is that date, as YYYY-MM-DD in UTC.
	RollingDate string
	// Reasons explains an empty pick: only-prerelease, no-running-version,
	// no-dates, no-candidates.
	Reasons map[string]string
}

// minOrderableShare is the share of a package's stable-looking versions that
// must parse under its scheme before the scheme's order is trusted over dates.
const minOrderableShare = 0.8

// mixedShapeShare is the share the rarer of calendar-year and ordinary majors
// needs for a package to count as having switched between CalVer and SemVer
// (home-assistant went from 0.118 to 2021.1).
const mixedShapeShare = 0.1

type entry struct {
	Candidate
	info Info
}

// Pick computes all outcomes. running may be empty. Candidates must already be
// free of malware; latest, safest and stable skip the ones marked Exposed and
// rolling keeps them. Duplicates by version string are merged, keeping the
// earliest date.
func Pick(ecosystem, running string, candidates []Candidate) Picks {
	scheme := SchemeFor(ecosystem)
	out := Picks{Scheme: scheme, Reasons: map[string]string{}}
	all := analyse(scheme, candidates)
	out.Rolling, out.RollingDate = pickRolling(scheme, all)
	if out.RollingDate == "" {
		out.Reasons["rolling"] = "no-dates"
	}
	switch {
	case running == "":
		out.Reasons["parity"] = "no-running-version"
	case len(all) == 0:
		out.Reasons["parity"] = "no-candidates"
	default:
		out.Parity = pickParity(scheme, running, all)
	}
	entries := cleanEntries(all)
	if len(entries) == 0 {
		for _, k := range []string{"latest", "safest", "stable"} {
			out.Reasons[k] = "no-candidates"
		}
		if len(all) == 0 {
			out.Reasons["rolling"] = "no-candidates"
		}
		return out
	}
	out.Orderable = packageOrderable(scheme, entries)

	out.Latest = pickHighest(scheme, entries, out.Orderable)
	out.Safest = pickHighest(scheme, entries, out.Orderable)
	if out.Latest == "" {
		out.Reasons["latest"] = "only-prerelease"
		out.Reasons["safest"] = "only-prerelease"
	}
	switch {
	case running == "":
		out.Reasons["stable"] = "no-running-version"
	default:
		out.Stable = pickClosest(scheme, running, stableVersions(entries, out.Orderable))
		if out.Stable == "" {
			out.Reasons["stable"] = "only-prerelease"
		}
	}
	return out
}

// cleanEntries drops the exposed releases: latest, safest and stable are drawn
// from clean releases only.
func cleanEntries(all []entry) []entry {
	var out []entry
	for _, e := range all {
		if !e.Exposed {
			out = append(out, e)
		}
	}
	return out
}

// PickLatest returns the highest stable release (see Picks.Latest).
func PickLatest(ecosystem string, candidates []Candidate) string {
	scheme := SchemeFor(ecosystem)
	entries := cleanEntries(analyse(scheme, candidates))
	return pickHighest(scheme, entries, packageOrderable(scheme, entries))
}

// PickStable returns the stable release closest to running, "" when there is
// none or no running version.
func PickStable(ecosystem, running string, candidates []Candidate) string {
	scheme := SchemeFor(ecosystem)
	entries := cleanEntries(analyse(scheme, candidates))
	if running == "" {
		return ""
	}
	return pickClosest(scheme, running, stableVersions(entries, packageOrderable(scheme, entries)))
}

// PickRolling returns the distinct versions published on the most recent
// release date, highest first, and that date. Exposed releases count.
func PickRolling(ecosystem string, candidates []Candidate) ([]string, string) {
	scheme := SchemeFor(ecosystem)
	return pickRolling(scheme, analyse(scheme, candidates))
}

// PickRollingTarget resolves the rolling set to one fix target: the member
// closest to the running version, the highest when there is no running version.
// The caller still applies its own no-downgrade guard.
func PickRollingTarget(ecosystem, running string, rolling []string) string {
	scheme := SchemeFor(ecosystem)
	if running == "" {
		return highestOf(scheme, rolling)
	}
	return pickClosest(scheme, running, rolling)
}

func analyse(scheme string, clean []Candidate) []entry {
	byVersion := map[string]int{}
	var out []entry
	for _, c := range clean {
		v := strings.TrimSpace(c.Version)
		if v == "" {
			continue
		}
		if i, seen := byVersion[v]; seen {
			if c.PublishedAtMs != nil && (out[i].PublishedAtMs == nil || *c.PublishedAtMs < *out[i].PublishedAtMs) {
				out[i].PublishedAtMs = c.PublishedAtMs
			}
			continue
		}
		byVersion[v] = len(out)
		c.Version = v
		out = append(out, entry{Candidate: c, info: ClassifyScheme(scheme, v)})
	}
	return out
}

var yearMajor = regexp.MustCompile(`^v?(\d{4})\.`)

// packageOrderable decides whether the scheme's order can be trusted for this
// package. Most of its real versions must parse under the scheme (pre-releases
// and non-version refs such as floating tags do not count against it), the
// scheme must be orderable at all, and the package must not have switched
// between calendar-year and ordinary majors, where numeric order would put an
// old CalVer release above a newer SemVer one.
func packageOrderable(scheme string, entries []entry) bool {
	if s, ok := SchemeByID(scheme); ok && s.recencyOnly() {
		return false
	}
	var parsed, unparsed, yearShaped, otherShaped int
	thisYear := time.Now().UTC().Year()
	for _, e := range entries {
		switch {
		case e.info.Orderable && e.info.Stable:
			parsed++
			if m := yearMajor.FindStringSubmatch(e.Version); m != nil {
				if y, _ := strconv.Atoi(m[1]); y >= 1990 && y <= thisYear+1 {
					yearShaped++
					continue
				}
			}
			otherShaped++
		case !e.info.Orderable && !isRef(e.info):
			unparsed++
		}
	}
	if parsed == 0 || float64(parsed) < minOrderableShare*float64(parsed+unparsed) {
		return false
	}
	if yearShaped >= 2 && otherShaped >= 2 {
		if float64(min(yearShaped, otherShaped)) >= mixedShapeShare*float64(parsed) {
			return false
		}
	}
	return true
}

// isRef reports whether a string is a moving reference (floating tag, branch,
// digest) and not a malformed version.
func isRef(i Info) bool {
	for _, r := range i.Reasons {
		switch r {
		case ReasonFloatingTag, ReasonBranchRef, ReasonDigest:
			return true
		}
	}
	return false
}

// stableVersions lists the versions stable and closest-eligible: in an orderable
// package only those the scheme can order, otherwise every stable one.
func stableVersions(entries []entry, orderable bool) []string {
	var out []string
	for _, e := range entries {
		if e.info.Stable && (e.info.Orderable || !orderable) {
			out = append(out, e.Version)
		}
	}
	return out
}

// pickHighest is the latest/safest rule. Orderable packages take the highest
// stable version by scheme order, with the newer release date breaking a tie.
// Others take the newest stable release by date, then the highest by order,
// then the lexically greatest.
func pickHighest(scheme string, entries []entry, orderable bool) string {
	var pool []entry
	for _, e := range entries {
		if e.info.Stable && (e.info.Orderable || !orderable) {
			pool = append(pool, e)
		}
	}
	if len(pool) == 0 {
		return ""
	}
	better := func(a, b entry) bool { // a beats b
		if orderable {
			if c, ok := CompareScheme(scheme, a.Version, b.Version); ok && c != 0 {
				return c > 0
			}
			if c := cmpDate(a.PublishedAtMs, b.PublishedAtMs); c != 0 {
				return c > 0
			}
			return a.Version > b.Version
		}
		if c := cmpDate(a.PublishedAtMs, b.PublishedAtMs); c != 0 {
			return c > 0
		}
		if c, ok := CompareScheme(scheme, a.Version, b.Version); ok && c != 0 {
			return c > 0
		}
		return a.Version > b.Version
	}
	best := pool[0]
	for _, e := range pool[1:] {
		if better(e, best) {
			best = e
		}
	}
	return best.Version
}

// cmpDate orders optional timestamps; a missing one is older than any known one.
func cmpDate(a, b *int64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case *a < *b:
		return -1
	case *a > *b:
		return 1
	}
	return 0
}

var numRun = regexp.MustCompile(`[0-9]+`)

// numericCore returns the first three numeric components of a version, ignoring
// an epoch ("1:2.3" counts as 2.3).
func numericCore(v string) ([3]int, bool) {
	if i := strings.IndexByte(v, ':'); i > 0 && digitsRe.MatchString(v[:i]) {
		v = v[i+1:]
	}
	var out [3]int
	runs := numRun.FindAllString(v, 3)
	if len(runs) == 0 {
		return out, false
	}
	for i, r := range runs {
		n, err := strconv.Atoi(r)
		if err != nil {
			n = 1<<31 - 1
		}
		out[i] = n
	}
	return out, true
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// pickClosest returns the version nearest running, comparing the first three
// numeric components major first (|dMajor|, then |dMinor|, then |dPatch|). A
// tie goes to the higher version. When running has no numeric core there is
// nothing to measure against, so it returns the highest.
func pickClosest(scheme, running string, versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	r, ok := numericCore(running)
	if !ok {
		return highestOf(scheme, versions)
	}
	best, bestKey, have := "", [3]int{}, false
	for _, v := range versions {
		c, ok := numericCore(v)
		if !ok {
			continue
		}
		key := [3]int{absInt(c[0] - r[0]), absInt(c[1] - r[1]), absInt(c[2] - r[2])}
		switch {
		case !have || lessKey(key, bestKey):
			best, bestKey, have = v, key, true
		case key == bestKey && higher(scheme, v, best):
			best = v
		}
	}
	if !have {
		return highestOf(scheme, versions)
	}
	return best
}

// PickParity returns the candidate nearest to running (see Picks.Parity), ""
// when there is no running version or no candidate.
func PickParity(ecosystem, running string, candidates []Candidate) string {
	if running == "" {
		return ""
	}
	scheme := SchemeFor(ecosystem)
	all := analyse(scheme, candidates)
	if len(all) == 0 {
		return ""
	}
	return pickParity(scheme, running, all)
}

// pickParity compares by the scheme's full order, revision included, because
// a distribution's revisions are the point (1.36.1-r15 to 1.36.1-r29 is the
// same upstream release rebuilt). Versions the scheme cannot order fall back to
// the numeric-core nearest of pickClosest.
func pickParity(scheme, running string, all []entry) string {
	var above, below string
	ordered := false
	for _, e := range all {
		c, ok := CompareScheme(scheme, e.Version, running)
		if !ok {
			continue
		}
		ordered = true
		switch {
		case c == 0:
			return e.Version
		case c > 0:
			if above == "" || lower(scheme, e.Version, above) {
				above = e.Version
			}
		default:
			if below == "" || higher(scheme, e.Version, below) {
				below = e.Version
			}
		}
	}
	if !ordered {
		versions := make([]string, 0, len(all))
		for _, e := range all {
			versions = append(versions, e.Version)
		}
		return pickClosest(scheme, running, versions)
	}
	if above != "" {
		return above
	}
	return below
}

func lower(scheme, a, b string) bool {
	if c, ok := CompareScheme(scheme, a, b); ok && c != 0 {
		return c < 0
	}
	return a < b
}

func lessKey(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func higher(scheme, a, b string) bool {
	if c, ok := CompareScheme(scheme, a, b); ok && c != 0 {
		return c > 0
	}
	return a > b
}

func highestOf(scheme string, versions []string) string {
	best := ""
	for i, v := range versions {
		if i == 0 || higher(scheme, v, best) {
			best = v
		}
	}
	return best
}

// pickRolling follows the same two steps as latest: the version order first,
// the date second. When the scheme can order the package, the day is the release
// day of the highest dated version (a pre-release or a vulnerable one counts;
// malware never reaches here), so a point release on an old branch published
// after it does not move the day. When the package cannot be ordered, the day is
// the most recent one.
func pickRolling(scheme string, entries []entry) ([]string, string) {
	dayOf := func(e entry) string {
		return time.UnixMilli(*e.PublishedAtMs).UTC().Format("2006-01-02")
	}
	orderable := packageOrderable(scheme, entries)
	var latestDay string
	var anchor *entry
	days := map[string][]string{}
	for i, e := range entries {
		if e.PublishedAtMs == nil {
			continue
		}
		day := dayOf(e)
		days[day] = append(days[day], e.Version)
		if day > latestDay {
			latestDay = day
		}
		if orderable && e.info.Orderable && (anchor == nil || rollingBeats(scheme, e, *anchor)) {
			anchor = &entries[i]
		}
	}
	if latestDay == "" {
		return nil, ""
	}
	if anchor != nil {
		latestDay = dayOf(*anchor)
	}
	set := days[latestDay]
	sort.SliceStable(set, func(i, j int) bool { return higher(scheme, set[i], set[j]) })
	return set, latestDay
}

// rollingBeats reports whether a is above b in the scheme order; a tie goes to
// the later release, then the greater string.
func rollingBeats(scheme string, a, b entry) bool {
	if c, ok := CompareScheme(scheme, a.Version, b.Version); ok && c != 0 {
		return c > 0
	}
	if c := cmpDate(a.PublishedAtMs, b.PublishedAtMs); c != 0 {
		return c > 0
	}
	return a.Version > b.Version
}

// ── rolling codec ───────────────────────────────────────────────────────────

// RollingDelimiter separates versions in the encoded form of a rolling set. No
// concrete version in any scheme contains a comma (Maven uses it only in range
// syntax), and it is safe in shells, URLs, JSON and markdown tables.
const RollingDelimiter = ","

// rollingBad rejects what cannot be part of a concrete version: whitespace and
// the characters range syntax uses.
var rollingBad = regexp.MustCompile("[\\s,<>=*|]")

// EncodeRolling joins a rolling set into its scalar form. It fails when a
// version contains the delimiter or another range character, because decoding
// would then split or misread it.
func EncodeRolling(versions []string) (string, error) {
	for _, v := range versions {
		if v == "" {
			return "", fmt.Errorf("version: rolling set contains an empty version")
		}
		if rollingBad.MatchString(v) {
			return "", fmt.Errorf("version: %q cannot be encoded in a rolling set", v)
		}
	}
	return strings.Join(versions, RollingDelimiter), nil
}

// DecodeRolling splits the scalar form: it trims, drops empties and keeps the
// first occurrence of a duplicate. A version with a range character is an
// error.
func DecodeRolling(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, RollingDelimiter) {
		v := strings.TrimSpace(part)
		if v == "" || seen[v] {
			continue
		}
		if rollingBad.MatchString(v) {
			return nil, fmt.Errorf("version: %q is not a version", v)
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}
