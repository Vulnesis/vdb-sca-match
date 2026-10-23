package version

import "sort"

// registry maps a scheme id (the `id` field in schemes.json) to its algorithm.
// A test asserts the two stay in step: every catalogue entry has an algorithm and
// every algorithm has a catalogue entry.
var registry = map[string]algo{
	// SemVer family
	"semver":    semverAlgo{semverOpts{vPrefix: "optional", minParts: 3, maxParts: 3}},
	"cargo":     semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3, buildCompared: true, maxNum: "18446744073709551615"}},
	"nuget":     semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 1, maxParts: 4, foldCase: true, leadingZeros: true, noPreLeadingZeros: true, maxNum: "2147483647"}},
	"hex":       semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3}},
	"pub":       semverAlgo{semverOpts{vPrefix: "forbidden", minParts: 3, maxParts: 3, buildCompared: true, leadingZeros: true}},
	"swift":     semverAlgo{semverOpts{vPrefix: "optional", minParts: 2, maxParts: 3, leadingZeros: true, lax: true, laxBuild: true}},
	"go":        semverAlgo{semverOpts{vPrefix: "required", minParts: 1, maxParts: 3, goPseudo: true, buildStable: goBuildStable}},
	"helm":      semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 3, leadingZeros: true, noPreLeadingZeros: true}},
	"terraform": semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 8, leadingZeros: true, lax: true, bareLetterPre: true, emptyPartQuirk: true}},
	"julia":     semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 3, buildCompared: true, leadingZeros: true, lax: true, laxBuild: true, bareLetterPre: true, upperV: true, emptyBuildHighest: true}},
	"rebar3":    semverAlgo{semverOpts{vPrefix: "optional", minParts: 1, maxParts: 4, buildCompared: true, firstPreAsText: true, leadingZeros: true}},

	// qualifier family
	"pep440":   pep440Algo{},
	"conda":    condaAlgo{},
	"maven":    mavenAlgo{},
	"gradle":   gradleAlgo{},
	"rubygems": rubygemsAlgo{},

	// distro family
	"debian":  debianAlgo{},
	"rpm":     rpmAlgo{},
	"arch":    archAlgo{},
	"alpine":  alpineAlgoV,
	"wolfi":   wolfiAlgoV,
	"gentoo":  gentooAlgoV,
	"nix":     nixAlgo{},
	"bitnami": bitnamiAlgo{},
}

// ClassifyScheme judges one version string under the named scheme. An unknown
// scheme id yields an unorderable, unstable Info with the unparseable reason.
func ClassifyScheme(scheme, v string) Info {
	a, ok := registry[scheme]
	if !ok {
		return Info{Scheme: scheme, Reasons: []string{ReasonUnparseable}}
	}
	orderable, stable, reasons := a.classify(v)
	return Info{Scheme: scheme, Orderable: orderable, Stable: stable, Reasons: reasons}
}

// CompareScheme orders two versions under the named scheme. ok is false when
// either is not a version of the scheme.
func CompareScheme(scheme, a, b string) (int, bool) {
	impl, ok := registry[scheme]
	if !ok {
		return 0, false
	}
	return impl.compare(a, b)
}

// SchemeIDs lists every registered scheme id, sorted.
func SchemeIDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
