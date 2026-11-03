package match

import (
	"fmt"
	"sort"
	"strings"
)

// CanonicalEcosystem maps a PURL `type` to the ecosystem naming used by
// PackageVersion.ecosystem and the vdb-manager importer (internal/db/ecosystem.go).
// PURL types diverge from the registry naming for a few ecosystems — golang→go,
// gem→rubygems, composer→packagist — so a raw `LOWER(pv.ecosystem)=LOWER(purlType)`
// comparison under-matches those. Everything else is identity.
func CanonicalEcosystem(purlType string) string {
	switch strings.ToLower(strings.TrimSpace(purlType)) {
	case "golang":
		return "go"
	case "gem":
		return "rubygems"
	case "composer":
		return "packagist"
	case "python", "pip":
		return "pypi"
	default:
		return strings.ToLower(strings.TrimSpace(purlType))
	}
}

// ecosystemEvidence is the authoritative set of CVEAffected ecosystem signals for
// one canonical ecosystem: the registry collectionURL values a processor stamps,
// and the (lowercased) vendor names that denote it. CVEAffected has no ecosystem
// column, so these are the only reliable way to ecosystem-scope a name-based
// match. Keep in sync with vdb-manager's collectionURLToEcosystem / vendorToEcosystem
// (internal/db/ecosystem.go) and the per-source collectionURL constants + GHSA
// ecosystemMap in vdb-manager/scripts/go-processors/cmd/*.
var ecosystemEvidence = map[string]struct {
	urls    []string
	vendors []string
}{
	"npm":       {urls: []string{"https://registry.npmjs.org", "https://www.npmjs.com"}, vendors: []string{"npm"}},
	"pypi":      {urls: []string{"https://pypi.org", "https://pypi.python.org"}, vendors: []string{"pypi"}},
	"go":        {urls: []string{"https://pkg.go.dev", "https://golang.org/pkg"}, vendors: []string{"go"}},
	"maven":     {urls: []string{"https://repo.maven.apache.org/maven2", "https://search.maven.org"}, vendors: []string{"maven"}},
	"cargo":     {urls: []string{"https://crates.io"}, vendors: []string{"crates.io"}},
	"rubygems":  {urls: []string{"https://rubygems.org"}, vendors: []string{"rubygems"}},
	"nuget":     {urls: []string{"https://www.nuget.org", "https://nuget.org/packages", "https://api.nuget.org/v3/index.json"}, vendors: []string{"nuget"}},
	"packagist": {urls: []string{"https://packagist.org", "https://repo.packagist.org"}, vendors: []string{"packagist"}},
	"pub":       {urls: []string{"https://pub.dev"}, vendors: []string{"pub"}},
	"hex":       {urls: []string{"https://hex.pm", "https://repo.hex.pm"}, vendors: []string{"hex"}},
	"cran":      {urls: []string{"https://cran.r-project.org"}, vendors: []string{"cran"}},
	"julia":     {urls: []string{"https://juliahub.com", "https://pkg.julialang.org"}, vendors: []string{"julia"}},
	"swift":     {urls: []string{"https://swiftpackageindex.com"}, vendors: []string{"swifturl", "swift"}},
	"conan":     {urls: []string{"https://conan.io/center"}, vendors: []string{"conan"}},
	"homebrew":  {urls: []string{"https://formulae.brew.sh"}, vendors: []string{"homebrew"}},
	"alpine":    {urls: []string{"https://pkgs.alpinelinux.org"}, vendors: []string{"alpine"}},
	// Distributions, for OS packages (DistroEcosystem). Their advisories carry
	// the distribution's own versions, with backported fixes.
	"debian":    {urls: []string{"https://packages.debian.org", "https://security-tracker.debian.org"}, vendors: []string{"debian"}},
	"ubuntu":    {urls: []string{"https://launchpad.net", "https://ubuntu.com/security"}, vendors: []string{"ubuntu"}},
	"redhat":    {urls: []string{"https://access.redhat.com", "https://catalog.redhat.com", "https://www.redhat.com"}, vendors: []string{"red hat", "redhat"}},
	"rocky":     {urls: []string{"https://errata.rockylinux.org"}, vendors: []string{"rocky", "rocky linux"}},
	"almalinux": {urls: []string{"https://errata.almalinux.org"}, vendors: []string{"almalinux"}},
	"amazon":    {urls: []string{"https://alas.aws.amazon.com"}, vendors: []string{"amazon"}},
	"suse":      {urls: []string{"https://www.suse.com", "https://packagehub.suse.com"}, vendors: []string{"suse"}},
	"fedora":    {urls: []string{"https://bodhi.fedoraproject.org"}, vendors: []string{"fedora"}},
	"wolfi":     {urls: []string{"https://wolfi.dev", "https://images.chainguard.dev"}, vendors: []string{"wolfi", "chainguard"}},
	// The Arch Security Tracker (AVG groups). AUR rows are a user repository, not
	// the distribution, and stay under their own vendor.
	"arch": {urls: []string{"https://security.archlinux.org"}, vendors: []string{"arch"}},
}

// EcosystemEvidence resolves a PURL `type` (or canonical ecosystem) to its
// authoritative CVEAffected scoping values. ok is false when the ecosystem is
// empty or has no known mapping — callers must then fall back to looser matching
// (never silently match nothing). The returned canonical is always the normalized
// ecosystem name even when ok is false.
func EcosystemEvidence(eco string) (canonical string, registryURLs, vendors []string, ok bool) {
	canonical = CanonicalEcosystem(eco)
	if canonical == "" {
		return "", nil, nil, false
	}
	ev, found := ecosystemEvidence[canonical]
	if !found {
		return canonical, nil, nil, false
	}
	return canonical, ev.urls, ev.vendors, true
}

// RegistryEcosystem is the package registry a purl names (npm, pypi, maven and
// the rest of ecosystemEvidence's registries), or "" for a distribution
// package, a generic purl or a type with no evidence. Matched by name alone,
// npm's tar@6.2.1 met GNU tar's and Debian's tar records, and the alias rules
// dropped twelve of npm's own CVEs.
func RegistryEcosystem(purl string) string {
	s, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	typ, _, ok := strings.Cut(s, "/")
	if !ok {
		return ""
	}
	eco := CanonicalEcosystem(typ)
	if _, known := ecosystemEvidence[eco]; !known || distributions[eco] {
		return ""
	}

	return eco
}

// distributions are the ecosystemEvidence keys that are operating system
// distributions rather than package registries.
var distributions = map[string]bool{
	"alpine": true, "debian": true, "ubuntu": true, "redhat": true, "rocky": true,
	"almalinux": true, "amazon": true, "suse": true, "fedora": true, "wolfi": true, "arch": true,
}

// nativeOnlyClauses keeps advisories that belong to no package registry and
// no distribution: an empty collectionURL and a vendor that is not one of the
// ecosystems above. Placeholders: $1 the package name, $2 every ecosystem
// vendor, $3 the registry collectionURLs and $4 the registry vendors.
//
// A row alone is not enough. NVD files CVE-2024-21485 as vendor "plotly",
// product "dash", with no registry, while GitHub and OSV file the same CVE
// under PyPI; read alone, the NVD row matched Debian's dash shell. So a row is
// also dropped when its CVE, or an alias of it, names the same package under a
// package registry, and when its CPE names a target platform
// (ANCHORE-2025-31049 is a WordPress theme called Dash). OSV stores each
// record's ecosystem as the vendor (openSUSE:Tumbleweed, openEuler:24.03-LTS,
// TuxCare:AlmaLinux:9.2, opam, Echo), and far more ecosystems than the table
// above, so an OSV row with a vendor is never native; OSS-Fuzz, whose records
// are upstream projects, is the exception. A distribution row
// for the same name does not drop it: Ubuntu filing a glibc CVE is the same
// glibc.
func nativeOnlyClauses() (outer, inner string, args []any) {
	var vendors, regURLs, regVendors []string
	for eco, ev := range ecosystemEvidence {
		vendors = append(vendors, ev.vendors...)
		if !distributions[eco] {
			regURLs = append(regURLs, ev.urls...)
			regVendors = append(regVendors, ev.vendors...)
		}
	}
	sort.Strings(vendors)
	sort.Strings(regURLs)
	sort.Strings(regVendors)

	return nativeClause("a"), nativeClause("ai"), []any{vendors, regURLs, regVendors}
}

// cpeTargetSW matches a CPE 2.3 string whose target_sw field (the tenth) names
// a platform rather than * or -.
const cpeTargetSW = `cpe:2\.3:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:*-][^:]*:`

// registryFiled is every CVE id an advisory files against the package ($1)
// under a registry ($3 URLs, $4 vendors), with the ids aliased to them. It
// does not depend on the candidate row, so Postgres reads it once and hashes
// it. Written as a correlated NOT EXISTS with the alias lookups OR'd in, it
// ran the lookups once per candidate and registry row pair: openssl's
// upstream pass ran past four minutes.
const registryFiled = `
		  SELECT r."cveId" AS id FROM "CVEAffected" r
		  WHERE LOWER(COALESCE(r."packageName", r.product)) = LOWER($1)
		    AND (RTRIM(LOWER(COALESCE(r."collectionURL", '')), '/') = ANY($3::text[])
		         OR LOWER(split_part(COALESCE(r."vendor", ''), ':', 1)) = ANY($4::text[]))`

func nativeClause(alias string) string {
	return fmt.Sprintf(`(COALESCE(%[1]s."collectionURL", '') = ''
		AND LOWER(split_part(COALESCE(%[1]s."vendor", ''), ':', 1)) <> ALL($2::text[])
		AND NOT (%[1]s.source = 'osv' AND COALESCE(%[1]s."vendor", '') <> '' AND LOWER(%[1]s."vendor") NOT LIKE 'oss-fuzz%%')
		AND COALESCE(%[1]s.cpes::text, '') !~ '%[2]s'
		AND NOT EXISTS (
		  SELECT 1 FROM (
		    SELECT f.id FROM (%[3]s) f
		    UNION SELECT al."primaryCveId" FROM "CVEAlias" al JOIN (%[3]s) f ON al."aliasCveId" = f.id
		    UNION SELECT al."aliasCveId" FROM "CVEAlias" al JOIN (%[3]s) f ON al."primaryCveId" = f.id
		  ) filed
		  WHERE filed.id = %[1]s."cveId"))`, alias, cpeTargetSW, registryFiled)
}
