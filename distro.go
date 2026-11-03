package match

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DistroEcosystem names the distribution an OS package's purl comes from, as
// an ecosystem MatchDependency restricts advisories to: "alpine", "debian",
// "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora", "wolfi"
// or "arch". It returns "" for anything that is not a deb, rpm, apk or alpm
// package with a namespace or distro qualifier it knows.
//
// A distribution backports fixes without moving the upstream version, so
// libc6 2.36-9+deb12u4 can be fixed for a CVE whose upstream range still
// covers 2.36. Matching such a package against upstream ranges reports flaws
// the distribution already fixed; its own advisories carry its own versions.
func DistroEcosystem(purl string) string {
	s, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	typ, rest, ok := strings.Cut(s, "/")
	if !ok {
		return ""
	}
	typ = strings.ToLower(typ)
	if typ != "deb" && typ != "rpm" && typ != "apk" && typ != "alpm" {
		return ""
	}
	namespace, _, _ := strings.Cut(rest, "/")
	distro := ""
	if _, query, found := strings.Cut(rest, "?"); found {
		if q, err := url.ParseQuery(query); err == nil {
			distro = q.Get("distro")
		}
	}

	return distroName(strings.ToLower(namespace), strings.ToLower(distro))
}

func distroName(namespace, distro string) string {
	for _, v := range []string{distro, namespace} {
		switch {
		case v == "":
			continue
		case strings.HasPrefix(v, "alpine"):
			return "alpine"
		case strings.HasPrefix(v, "wolfi"), strings.HasPrefix(v, "chainguard"):
			return "wolfi"
		case strings.HasPrefix(v, "debian"):
			return "debian"
		case strings.HasPrefix(v, "ubuntu"):
			return "ubuntu"
		case strings.HasPrefix(v, "rhel"), strings.HasPrefix(v, "redhat"), strings.HasPrefix(v, "centos"):
			return "redhat"
		case strings.HasPrefix(v, "rocky"):
			return "rocky"
		case strings.HasPrefix(v, "almalinux"), strings.HasPrefix(v, "alma"):
			return "almalinux"
		case strings.HasPrefix(v, "amzn"), strings.HasPrefix(v, "amazon"):
			return "amazon"
		case strings.HasPrefix(v, "sles"), strings.HasPrefix(v, "suse"), strings.HasPrefix(v, "opensuse"):
			return "suse"
		case strings.HasPrefix(v, "fedora"):
			return "fedora"
		case v == "arch", strings.HasPrefix(v, "archlinux"), strings.HasPrefix(v, "cachyos"),
			strings.HasPrefix(v, "manjaro"), strings.HasPrefix(v, "endeavouros"):
			return "arch"
		}
	}

	return ""
}

var apkRevision = regexp.MustCompile(`-r[0-9]+$`)

// UpstreamVersion strips what a distribution adds to the upstream version: the
// epoch, the Debian or RPM revision, Alpine's -rN, and repack markers such as
// +dfsg. "+really" names the version actually shipped, so 5.6.1+really5.4.5
// is 5.4.5.
func UpstreamVersion(distro, v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		v = v[i+1:]
	}
	switch distro {
	case "alpine", "wolfi":
		v = apkRevision.ReplaceAllString(v, "")
	case "debian", "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora", "arch":
		if i := strings.LastIndexByte(v, '-'); i > 0 {
			v = v[:i]
		}
	default:
		return v
	}
	if _, after, ok := strings.Cut(v, "+really"); ok {
		v = after
	}
	for _, marker := range []string{"+dfsg", "+ds", "~"} {
		if i := strings.Index(v, marker); i > 0 {
			v = v[:i]
		}
	}

	return v
}

// MatchOSPackage matches a package a distribution ships. The distribution's
// advisories decide where they speak: every CVE they report affected is
// kept, and an upstream CVE they mention for this package without reporting
// this version affected (fixed or not affected there) is dropped. An upstream
// CVE the distribution does not mention at all is kept, matched on the
// upstream version, so thin distribution data never hides a flaw.
//
// distro is DistroEcosystem's answer; empty falls back to MatchDependency.
// source is the source package (DistroSource): libc6 is built from glibc,
// distribution advisories often name the source, and upstream advisories
// always name the project, so the upstream pass uses it when known.
func MatchOSPackage(ctx context.Context, q Querier, dep Dependency, distro, source string) ([]Match, error) {
	if distro == "" {
		return MatchDependency(ctx, q, dep)
	}
	names := []string{dep.Name}
	if source != "" && !strings.EqualFold(source, dep.Name) {
		names = append(names, source)
	}

	have := map[string]bool{}
	var out []Match
	for _, name := range names {
		distroDep := dep
		distroDep.Name = name
		distroDep.Ecosystem = distro
		reported, err := MatchDependency(ctx, q, distroDep)
		if err != nil {
			return nil, err
		}
		for _, m := range reported {
			// A distribution row that says only "every version" carries no
			// version information; it neither reports this build affected nor
			// speaks for it (cve.org files such rows under distribution names).
			if strings.Contains(m.Method, "wildcard") {
				continue
			}
			// A distribution fixes each release branch separately: "< 3.3.3-r0"
			// is the fix on the branch that ships OpenSSL 3.3 and says nothing
			// about 3.1.8 on an older release. Not for a distribution whose
			// rows are already one stream (singleStream).
			if !singleStream(distro) && !sameBranch(distro, dep.Version, m.VulnerableRange) {
				continue
			}
			if !have[m.CveID] {
				have[m.CveID] = true
				out = append(out, m)
			}
		}
	}

	upDep := dep
	upDep.Name = names[len(names)-1]
	upDep.Ecosystem = ""
	upDep.NativeOnly = true
	upDep.Version = UpstreamVersion(distro, dep.Version)
	upstream, err := MatchDependency(ctx, q, upDep)
	if err != nil {
		return nil, err
	}
	var candidates []string
	for _, m := range upstream {
		if !have[m.CveID] {
			candidates = append(candidates, m.CveID)
		}
	}
	mentioned, err := distroMentions(ctx, q, names, distro, dep.Release, candidates)
	if err != nil {
		return nil, fmt.Errorf("distribution advisories for %s: %w", dep.Key, err)
	}
	for _, m := range upstream {
		if !have[m.CveID] && !mentioned[m.CveID] {
			have[m.CveID] = true
			m.Method = appendMethod(m.Method, "upstream:distro-silent")
			out = append(out, m)
		}
	}

	return out, nil
}

// releaseClause keeps a row that names release $n, or one that names no
// release when release $n has no row of its own for the package and CVE.
// OSV tags a distribution row with its release (Debian:12, Alpine:v3.18,
// Ubuntu:22.04:LTS), and a fix on Debian 13 at 1.34+dfsg-1.3 says nothing
// about Debian 12's 1.34+dfsg-1.2+deb12u1; read across releases it flagged a
// version Debian 12 had fixed. An untagged row is one branch's fix too:
// cve.org's "alpine busybox < 1.36.1-r25" is Alpine 3.21's, while
// ALPINE-CVE-2023-42366 fixes Alpine 3.18 at 1.36.1-r6. The release's own
// rows are found under the CVE id or the distribution's (ALPINE-CVE-...).
// $1 is the package name.
func releaseClause(alias string, n int) string {
	return fmt.Sprintf(`(LOWER(%[1]s."vendor") = $%[2]d OR LOWER(%[1]s."vendor") LIKE $%[2]d || ':%%'
		OR (POSITION(':' IN COALESCE(%[1]s."vendor", '')) = 0
		    AND NOT EXISTS (
		      SELECT 1 FROM "CVEAffected" rr
		      WHERE rr."cveId" IN (%[1]s."cveId", UPPER(split_part($%[2]d, ':', 1)) || '-' || %[1]s."cveId")
		        AND (LOWER(rr."vendor") = $%[2]d OR LOWER(rr."vendor") LIKE $%[2]d || ':%%')
		        AND LOWER(COALESCE(rr."packageName", rr.product)) = LOWER($1))))`, alias, n)
}

var debianCodenames = map[string]string{
	"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

// DistroRelease is the release a distribution purl names, as OSV writes it in
// a row's vendor ("debian:12", "ubuntu:22.04", "alpine:v3.18"), or "" when
// the purl names none or the distribution is not one OSV tags by release.
func DistroRelease(purl string) string {
	_, query, ok := strings.Cut(purl, "?")
	if !ok {
		return ""
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	d := strings.ToLower(strings.TrimSpace(q.Get("distro")))
	switch DistroEcosystem(purl) {
	case "debian":
		v := strings.TrimLeft(strings.TrimPrefix(d, "debian"), "-_ ")
		if c, ok := debianCodenames[v]; ok {
			v = c
		}
		v, _, _ = strings.Cut(v, ".")
		if v == "" || strings.Trim(v, "0123456789") != "" {
			return ""
		}
		return "debian:" + v
	case "ubuntu":
		v := strings.TrimLeft(strings.TrimPrefix(d, "ubuntu"), "-_ ")
		if parts := strings.SplitN(v, ".", 3); len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return "ubuntu:" + parts[0] + "." + parts[1]
		}
	case "alpine":
		v := strings.TrimLeft(strings.TrimPrefix(d, "alpine"), "-_ v")
		if parts := strings.SplitN(v, ".", 3); len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return "alpine:v" + parts[0] + "." + parts[1]
		}
	case "amazon":
		// amazon-2023, amzn-2023, amzn2023, amazonlinux-2: the release line
		// ("2023", "2") the Amazon Linux rows are tagged with.
		v := d
		for _, p := range []string{"amazonlinux", "amazon", "amzn"} {
			if rest, ok := strings.CutPrefix(v, p); ok {
				v = rest
				break
			}
		}
		v, _, _ = strings.Cut(strings.TrimLeft(v, "-_ "), ".")
		if v != "" && strings.Trim(v, "0123456789") == "" {
			return "amazon:" + v
		}
	}

	return ""
}

// singleStream reports whether a distribution's advisory rows already say
// which build they fix, so that an installed version on another upstream
// branch than the fix is still judged by version. Arch is rolling: one stream,
// and 3.2.1 is below the fix at 3.3.0. Amazon Linux rows are tagged with their
// release (DistroRelease) and each release is one linear stream of builds that
// moves between upstream branches (curl 8.0.1 to 8.5.0 to 8.11.1). sameBranch
// is for the untagged rows of distributions that backport on a fixed branch.
func singleStream(distro string) bool {
	return distro == "arch" || distro == "amazon"
}

// EpochVersion is the version to match an rpm package of Amazon Linux by. The
// sensor writes an rpm's version as version-release and carries a non-zero
// epoch in the purl's epoch qualifier, while advisory rows hold the full
// epoch:version-release: openssl-libs 3.0.8-1 with epoch 1 is 1:3.0.8-1, and
// without the epoch it would read as epoch 0, below every fix. Anything
// else, and a version that already names its epoch, comes back unchanged.
func EpochVersion(purl, version string) string {
	if DistroEcosystem(purl) != "amazon" || version == "" {
		return version
	}
	if i := strings.IndexByte(version, ':'); i > 0 && strings.Trim(version[:i], "0123456789") == "" {
		return version
	}
	_, query, ok := strings.Cut(purl, "?")
	if !ok {
		return version
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return version
	}
	e := strings.TrimSpace(q.Get("epoch"))
	if e == "" || e == "0" || strings.Trim(e, "0123456789") != "" {
		return version
	}

	return e + ":" + version
}

// DistroSource is the source package a distribution purl names in its
// upstream qualifier (pkg:deb/debian/libc6@...?upstream=glibc), or "".
func DistroSource(purl string) string {
	_, query, ok := strings.Cut(purl, "?")
	if !ok {
		return ""
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(q.Get("upstream"))
}

// distroMentions returns which of the CVEs the distribution has any advisory
// row for, under any of the package's names.
func distroMentions(ctx context.Context, q Querier, names []string, distro, release string, cves []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, name := range names {
		got, err := distroMentionsFor(ctx, q, name, distro, release, cves)
		if err != nil {
			return nil, err
		}
		for id := range got {
			out[id] = true
		}
	}

	return out, nil
}

func distroMentionsFor(ctx context.Context, q Querier, name, distro, release string, cves []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 || name == "" {
		return out, nil
	}
	outer, _, ecoArgs := versionRangeEcoClauses(distro)
	if rel := strings.TrimSpace(release); rel != "" {
		outer = fmt.Sprintf(`(%s) AND %s`, outer, releaseClause("a", len(ecoArgs)+2))
		ecoArgs = append(ecoArgs, strings.ToLower(rel))
	}
	args := append([]any{name}, ecoArgs...)
	args = append(args, cves, strings.ToUpper(distro)+"-")
	// A distribution's row can sit under an alias of the CVE: OSV files
	// Debian's verdict on CVE-2023-39804 as DEBIAN-CVE-2023-39804. Looking for
	// the bare id only read Debian as silent and reported a CVE its
	// 1.34+dfsg-1.2+deb12u1 fix closed. One alias hop, plus the
	// distribution's own id for any CVE that hop reaches
	// (ANCHORE-2023-39804 aliases CVE-2023-39804, not the Debian record); a
	// second general hop would pass through advisories such as DSA-5673-1
	// that alias many CVEs and tie unrelated ones together.
	rows, err := q.Query(ctx, fmt.Sprintf(`
		WITH hop AS (
		  SELECT c AS cve, c AS id FROM unnest($%[3]d::text[]) c
		  UNION SELECT al."primaryCveId", al."aliasCveId" FROM "CVEAlias" al WHERE al."primaryCveId" = ANY($%[3]d::text[])
		  UNION SELECT al."aliasCveId", al."primaryCveId" FROM "CVEAlias" al WHERE al."aliasCveId" = ANY($%[3]d::text[])
		), ids AS (
		  SELECT cve, id FROM hop
		  UNION SELECT cve, $%[4]d || id FROM hop WHERE id LIKE 'CVE-%%'
		)
		SELECT DISTINCT ids.cve FROM ids JOIN "CVEAffected" a ON a."cveId" = ids.id
		WHERE %[1]s AND (%[2]s)
		  AND EXISTS (SELECT 1 FROM "CVEAffectedVersion" v WHERE v."affectedId" = a.uuid
		      AND (COALESCE(v."lessThan", '') <> '' OR COALESCE(v."lessThanOrEqual", '') <> ''
		           OR COALESCE(v.version, '') NOT IN ('', '*', '0', 'n/a')))`,
		nameMatchExpr("a", false), outer, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}

	return out, rows.Err()
}

var rangeBound = regexp.MustCompile(`<=?\s*([^\s,<>=]+)`)

// sameBranch reports whether a range's upper bound is on the installed
// version's upstream branch (major.minor). A range with no upper bound, or a
// version with no minor, is taken as on the branch.
func sameBranch(distro, installed, vulnerableRange string) bool {
	m := rangeBound.FindAllStringSubmatch(vulnerableRange, -1)
	if len(m) == 0 {
		return true
	}
	have := branchOf(UpstreamVersion(distro, installed))
	bound := branchOf(UpstreamVersion(distro, m[len(m)-1][1]))
	if have == "" || bound == "" {
		return true
	}

	return have == bound
}

func branchOf(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}

	return parts[0] + "." + minor
}
