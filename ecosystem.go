package match

import (
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

// nativeOnlyClauses keeps advisories that belong to no package registry and
// no distribution: an empty collectionURL and a vendor that is not one of the
// ecosystems above. Placeholders $2 for the vendors, as versionRangeEcoClauses.
func nativeOnlyClauses() (outer, inner string, args []any) {
	vendors := make([]string, 0, len(ecosystemEvidence)*2)
	for _, ev := range ecosystemEvidence {
		vendors = append(vendors, ev.vendors...)
	}
	sort.Strings(vendors)
	outer = `(COALESCE(a."collectionURL", '') = '' AND LOWER(split_part(COALESCE(a."vendor", ''), ':', 1)) <> ALL($2::text[]))`
	inner = `(COALESCE(ai."collectionURL", '') = '' AND LOWER(split_part(COALESCE(ai."vendor", ''), ':', 1)) <> ALL($2::text[]))`

	return outer, inner, []any{vendors}
}
