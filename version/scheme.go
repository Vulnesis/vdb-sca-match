package version

import (
	"regexp"
	"strings"
)

// Info is what a scheme's rules say about one version string.
type Info struct {
	// Scheme is the catalogue id of the scheme that judged the string.
	Scheme string
	// Orderable is false when the string is not a version of the scheme (a
	// branch, a floating tag, a query), so it can neither be ordered nor stable.
	Orderable bool
	// Stable is true when a stable-release filter keeps the version.
	Stable bool
	// Reasons names why a version is unstable (prerelease, dev, snapshot,
	// nightly, build-metadata, local-version, pseudo-version, branch-ref,
	// floating-tag, unparseable, ...). Empty when Stable.
	Reasons []string
}

// algo is one scheme's comparator and stability rule. Implementations are
// stateless and registered by scheme id in registry (see schemes_registry.go).
type algo interface {
	// classify reports whether v is a version of the scheme and whether a
	// stable-release filter keeps it.
	classify(v string) (orderable, stable bool, reasons []string)
	// compare orders two versions. ok is false when either string is not a
	// version of the scheme; the caller must not fall back to string order.
	compare(a, b string) (cmp int, ok bool)
}

// Reason tokens. The set is closed: schemes.json and the test vectors use only
// these, so a consumer can switch over them.
const (
	ReasonPrerelease    = "prerelease"
	ReasonDev           = "dev"
	ReasonSnapshot      = "snapshot"
	ReasonNightly       = "nightly"
	ReasonBuildMetadata = "build-metadata"
	ReasonLocalVersion  = "local-version"
	ReasonPseudoVersion = "pseudo-version"
	ReasonBranchRef     = "branch-ref"
	ReasonCanary        = "canary"
	ReasonEdge          = "edge"
	ReasonFloatingTag   = "floating-tag"
	ReasonDigest        = "digest"
	ReasonGitSnapshot   = "git-snapshot"
	ReasonOddMinor      = "odd-minor-unstable"
	ReasonUnparseable   = "unparseable"
	// ReasonCalverShape is informational and may accompany a stable version.
	ReasonCalverShape = "calver-shape"
)

// ReasonMilestone marks a Maven-style milestone build (1.0-M1, 1.0-milestone-2).
const ReasonMilestone = "milestone"

var channelTokenRe = regexp.MustCompile(`[A-Za-z]+|[0-9]+`)

// channelReasons maps the channel words found in a pre-release or build string
// to their specific reason tokens (dev, snapshot, nightly, milestone). It does
// not report plain pre-release words (alpha, beta, rc); callers add
// ReasonPrerelease themselves so each scheme can decide whether the specific
// reason replaces it or accompanies it.
func channelReasons(s string) []string {
	var out []string
	add := func(r string) {
		for _, x := range out {
			if x == r {
				return
			}
		}
		out = append(out, r)
	}
	toks := channelTokenRe.FindAllString(strings.ToLower(s), -1)
	for i, t := range toks {
		switch t {
		case "dev", "devel":
			add(ReasonDev)
		case "snapshot":
			add(ReasonSnapshot)
		case "nightly", "canary":
			add(ReasonNightly)
		case "milestone":
			add(ReasonMilestone)
		case "m":
			if i+1 < len(toks) && isDigit(toks[i+1][0]) {
				add(ReasonMilestone)
			}
		}
	}
	return out
}

func unparseable() (bool, bool, []string) {
	return false, false, []string{ReasonUnparseable}
}

func verdict(reasons ...string) (orderable, stable bool, out []string) {
	if len(reasons) == 0 {
		return true, true, nil
	}
	return true, false, reasons
}
