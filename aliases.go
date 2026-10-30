package match

import (
	"context"
	"strings"
)

// coarseMethodTokens are method labels whose evidence carries no usable version
// math. When a CVE's alias group has specific version evidence these tokens are
// stripped from a surviving (specific) match, and a match with ONLY these tokens
// is dropped entirely.
var coarseMethodTokens = map[string]struct{}{
	"cpe":                    {},
	"purl:coarse":            {},
	"version-range:wildcard": {},
	"version-range:unknown":  {},
}

// resolveAliasGroups maps each input cveId to a canonical group root such that
// aliased ids (via the CVEAlias table) share a root. One batched query plus an
// in-memory union-find over the input set — a non-matched bridge node cannot
// contribute package evidence we'd miss, so depth-1 is sufficient at match scale.
func resolveAliasGroups(ctx context.Context, q Querier, cveIds []string) (map[string]string, error) {
	uf := newUnionFind(cveIds)
	if len(cveIds) == 0 {
		return uf.roots(), nil
	}

	rows, err := q.Query(ctx, `
		SELECT "primaryCveId", "aliasCveId"
		FROM "CVEAlias"
		WHERE "primaryCveId" = ANY($1) OR "aliasCveId" = ANY($1)`,
		cveIds,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var primary, alias string
		if err := rows.Scan(&primary, &alias); err != nil {
			continue
		}
		// Union only when BOTH endpoints are in the matched set; an edge through
		// a non-matched bridge node carries no package evidence for us.
		if uf.has(primary) && uf.has(alias) {
			uf.union(primary, alias)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return uf.roots(), nil
}

// applyWildcardSuppression deletes wildcard/coarse-only matches in any alias
// group that has specific affected-version evidence (collated from facts across
// the group). Matches that have specific evidence of their own are kept, with
// their coarse method tokens stripped. Groups with no specific evidence anywhere
// are left untouched (Rule 2 — a genuine all-versions "*" stays valid).
func applyWildcardSuppression(seen map[string]Match, facts map[string]affectedFacts, groupOf map[string]string) {
	groupKey := func(id string) string {
		if groupOf != nil {
			if g, ok := groupOf[id]; ok {
				return g
			}
		}
		return id // fail-soft: singleton group
	}

	// Aggregate specific evidence per group from ALL facts (including cveIds that
	// produced a fact but no surviving match — e.g. a specific range the
	// installed version sits above).
	//
	// What counts as specific depends on what the wildcard is. A bounded range says the
	// package was fixed, which contradicts any "all versions" claim. An enumerated exact
	// version does too, EXCEPT next to an open-ended "introduced X, never fixed" range:
	// OSV lists the affected releases beside that range as `versions`, so they are the
	// range spelled out. Treating them as contradicting it hid whole-package malware
	// (MAL-2025-653 eslint-v9) from every install that was not one of the listed releases.
	groupBounded := map[string]bool{}
	groupAnySpecific := map[string]bool{}
	groupOpenRange := map[string]bool{}
	for cveID, f := range facts {
		g := groupKey(cveID)
		if f.hasBounded {
			groupBounded[g] = true
		}
		if f.hasSpecific {
			groupAnySpecific[g] = true
		}
		if f.hasOpenRange {
			groupOpenRange[g] = true
		}
	}
	groupHasSpecific := map[string]bool{}
	for g := range groupAnySpecific {
		groupHasSpecific[g] = groupBounded[g] || !groupOpenRange[g]
	}

	for cveID, m := range seen {
		if !groupHasSpecific[groupKey(cveID)] {
			continue // Rule 2 — nothing specific in this group; keep as-is
		}
		if m.isSpecific {
			m.Method = stripCoarseMethods(m.Method)
			seen[cveID] = m
			continue
		}
		// An ecosystem's own advisory database is the authority on whether a fix exists
		// for it: RustSec writes "introduced 0, no patched version" for rsa's Marvin
		// attack, while GitHub and cve.org record only the "<= 0.9.6" seen at report time.
		// The aggregator's bound does not retract the ecosystem's statement.
		if m.isWildcard && ecosystemAuthoritative(cveID) && facts[cveID].hasOpenRange {
			continue
		}
		// Wildcard/coarse-only evidence in a group that has specifics → false
		// positive. Discard.
		delete(seen, cveID)
	}
}

// stripCoarseMethods removes coarse tokens from a comma-separated method list,
// preserving order and any specific tokens.
func stripCoarseMethods(method string) string {
	if method == "" {
		return ""
	}
	parts := strings.Split(method, ",")
	kept := parts[:0]
	for _, p := range parts {
		if _, coarse := coarseMethodTokens[p]; coarse {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, ",")
}

// unionKeys returns the union of the keys of seen and facts.
func unionKeys(seen map[string]Match, facts map[string]affectedFacts) []string {
	set := make(map[string]struct{}, len(seen)+len(facts))
	for id := range seen {
		set[id] = struct{}{}
	}
	for id := range facts {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out
}

// ── union-find ───────────────────────────────────────────────────────────────

type unionFind struct {
	parent map[string]string
}

func newUnionFind(ids []string) *unionFind {
	parent := make(map[string]string, len(ids))
	for _, id := range ids {
		parent[id] = id
	}
	return &unionFind{parent: parent}
}

func (u *unionFind) has(id string) bool {
	_, ok := u.parent[id]
	return ok
}

func (u *unionFind) find(id string) string {
	root := id
	for u.parent[root] != root {
		root = u.parent[root]
	}
	// path compression
	for u.parent[id] != root {
		u.parent[id], id = root, u.parent[id]
	}
	return root
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

func (u *unionFind) roots() map[string]string {
	out := make(map[string]string, len(u.parent))
	for id := range u.parent {
		out[id] = u.find(id)
	}
	return out
}

// ecosystemAuthoritative reports an advisory id issued by the package ecosystem's own
// vulnerability database, whose "never fixed" outranks an aggregator's bounded range.
func ecosystemAuthoritative(id string) bool {
	u := strings.ToUpper(strings.TrimSpace(id))
	return strings.HasPrefix(u, "RUSTSEC-") || strings.HasPrefix(u, "GO-")
}
