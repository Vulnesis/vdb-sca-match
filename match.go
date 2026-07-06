package match

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// Match represents one CVE matched against a dependency.
type Match struct {
	CveID           string
	Source          string
	Method          string // e.g. "version-range:lessThan", "purl", "cpe", "crit"
	VulnerableRange string // the range expression that matched

	// Internal annotations used only by the wildcard-suppression pass; they are
	// zeroed before MatchDependency returns and never serialised.
	isWildcard bool // evidence is an "all versions" ("*") signal
	isCoarse   bool // evidence has no version math (cpe / version-less purl / inconclusive range)
	isSpecific bool // matched an exact version or a bounded range
}

// MatchDependency runs all match methods for a single dependency and returns
// the union of matched CVEs. Each method fails soft (log+skip) so one bad path
// can't drop the dependency.
func MatchDependency(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	seen := map[string]Match{}

	// add merges a match into the dedup map keyed by CveID. A CVE reached by
	// several methods keeps every method (folded into Method for the consumer's
	// Triage.analysisDetail) and the first non-empty VulnerableRange — which,
	// because version-range runs first, is the most informative range.
	add := func(mm Match) {
		if ex, ok := seen[mm.CveID]; ok {
			ex.Method = appendMethod(ex.Method, mm.Method)
			if ex.VulnerableRange == "" {
				ex.VulnerableRange = mm.VulnerableRange
			}
			if ex.Source == "" {
				ex.Source = mm.Source
			}
			// Fold specificity so a CVE reached by several methods carries every
			// kind of evidence (e.g. version-range:specific + cpe:coarse).
			ex.isWildcard = ex.isWildcard || mm.isWildcard
			ex.isCoarse = ex.isCoarse || mm.isCoarse
			ex.isSpecific = ex.isSpecific || mm.isSpecific
			seen[mm.CveID] = ex
			return
		}
		seen[mm.CveID] = mm
	}

	// 1. version-range matching (primary). Returns per-cveId affectedFacts used
	// by the wildcard-suppression pass below. This is the authoritative path, so
	// its error is hard: returning it lets callers distinguish "query failed"
	// from "no vulnerabilities" instead of silently reporting a clean bill.
	m, facts, err := matchVersionRange(ctx, q, dep)
	if err != nil {
		return nil, fmt.Errorf("version-range match for %s: %w", dep.Key, err)
	}
	for _, mm := range m {
		add(mm)
	}

	// 2. PURL-based registry lookup (precise)
	if m, err := matchPurl(ctx, q, dep); err != nil {
		log.Printf("[match] purl error for %s: %v", dep.Key, err)
	} else {
		for _, mm := range m {
			add(mm)
		}
	}

	// 3. CPE matching (coarse, only if CPE present)
	if dep.Cpe != "" {
		if m, err := matchCPE(ctx, q, dep); err != nil {
			log.Printf("[match] cpe error for %s: %v", dep.Key, err)
		} else {
			for _, mm := range m {
				add(mm)
			}
		}
	}

	// 3.5 Wildcard suppression: collate affected versions across each CVE's
	// alias group and discard over-broad "*"/coarse matches when the group has
	// specific version evidence. Fail-soft — on alias-query error each cveId is
	// its own singleton group (single-record Rule 1 still applies).
	if len(seen) > 0 {
		groupOf, err := resolveAliasGroups(ctx, q, unionKeys(seen, facts))
		if err != nil {
			log.Printf("[match] alias-group error for %s: %v", dep.Key, err)
			groupOf = nil
		}
		applyWildcardSuppression(seen, facts, groupOf)
	}

	// 4. CRIT tagging — runs AFTER suppression so it never resurrects or tags a
	// dropped CVE (only over the surviving matched cveIds).
	if len(seen) > 0 {
		cveIds := make([]string, 0, len(seen))
		for id := range seen {
			cveIds = append(cveIds, id)
		}
		if critIds, err := matchCrit(ctx, q, cveIds); err != nil {
			log.Printf("[match] crit error for %s: %v", dep.Key, err)
		} else {
			for _, id := range critIds {
				if m, ok := seen[id]; ok {
					m.Method = appendMethod(m.Method, "crit")
					seen[id] = m
				}
			}
		}
	}

	out := make([]Match, 0, len(seen))
	for _, m := range seen {
		// Strip internal annotations — they must never escape the package.
		m.isWildcard, m.isCoarse, m.isSpecific = false, false, false
		out = append(out, m)
	}
	return out, nil
}

// appendMethod adds method to a comma-separated method list, skipping it when
// already present so repeated hits (e.g. two version-range rows) don't duplicate.
func appendMethod(existing, method string) string {
	if existing == "" {
		return method
	}
	if method == "" {
		return existing
	}
	for _, m := range strings.Split(existing, ",") {
		if m == method {
			return existing
		}
	}
	return existing + "," + method
}
