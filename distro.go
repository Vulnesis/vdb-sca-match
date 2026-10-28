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
// "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora" or
// "wolfi". It returns "" for anything that is not a deb, rpm or apk package
// with a namespace or distro qualifier it knows.
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
	if typ != "deb" && typ != "rpm" && typ != "apk" {
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
	case "debian", "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora":
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
func MatchOSPackage(ctx context.Context, q Querier, dep Dependency, distro string) ([]Match, error) {
	if distro == "" {
		return MatchDependency(ctx, q, dep)
	}
	distroDep := dep
	distroDep.Ecosystem = distro
	reported, err := MatchDependency(ctx, q, distroDep)
	if err != nil {
		return nil, err
	}
	upDep := dep
	upDep.Ecosystem = ""
	upDep.NativeOnly = true
	upDep.Version = UpstreamVersion(distro, dep.Version)
	upstream, err := MatchDependency(ctx, q, upDep)
	if err != nil {
		return nil, err
	}

	have := make(map[string]bool, len(reported))
	for _, m := range reported {
		have[m.CveID] = true
	}
	var candidates []string
	for _, m := range upstream {
		if !have[m.CveID] {
			candidates = append(candidates, m.CveID)
		}
	}
	mentioned, err := distroMentions(ctx, q, dep.Name, distro, candidates)
	if err != nil {
		return nil, fmt.Errorf("distribution advisories for %s: %w", dep.Key, err)
	}
	out := reported
	for _, m := range upstream {
		if !have[m.CveID] && !mentioned[m.CveID] {
			m.Method = appendMethod(m.Method, "upstream:distro-silent")
			out = append(out, m)
		}
	}

	return out, nil
}

// distroMentions returns which of the CVEs the distribution has any advisory
// row for, for this package name.
func distroMentions(ctx context.Context, q Querier, name, distro string, cves []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 || name == "" {
		return out, nil
	}
	outer, _, ecoArgs := versionRangeEcoClauses(distro)
	args := append([]any{name}, ecoArgs...)
	args = append(args, cves)
	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT DISTINCT a."cveId" FROM "CVEAffected" a
		WHERE %s AND (%s) AND a."cveId" = ANY($%d::text[])`,
		nameMatchExpr("a", false), outer, len(args)), args...)
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
