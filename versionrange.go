package match

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	ver "github.com/Vulnetix/vdb-sca-match/version"
)

// affectedFacts summarises, per cveId, what affected-version evidence was seen
// for the package — independent of whether the installed version matched. It
// drives wildcard suppression: a specific affected range ANYWHERE in a CVE's
// alias group discards an over-broad "*".
type affectedFacts struct {
	hasWildcard bool
	hasSpecific bool // any exact version or bounded range (the union of the two below)

	// hasBounded: a range with a real upper bound. It says the package WAS fixed, so it
	// contradicts any claim that every version is affected.
	hasBounded bool
	// hasOpenRange: "introduced X, never fixed" (a concrete start, lessThan "*"). OSV
	// writes the enumerated releases next to it as `versions`; they are the range
	// spelled out, not a contradiction of it.
	hasOpenRange bool
}

// verChange is a CVE 5.1 in-range status step ({at, status}).
type verChange struct {
	at     string
	status string
}

// affRow is one CVEAffectedVersion row, normalised.
type affRow struct {
	status          string // lowercased: "affected" | "unaffected" | …
	versionType     string
	version         string
	lessThan        string
	lessThanOrEqual string
	changes         []verChange
}

// cveData groups the affected rows of one cveId by product (affectedId).
type cveData struct {
	source       string
	products     map[string][]affRow
	productOrder []string
}

// versionRangeCVELimit bounds the candidate CVE set per package. It is high
// enough that real packages (django carries a few hundred CVE/GHSA/PYSEC rows)
// are never truncated; the ordering below (most-recently-published first) means
// that if a pathological package ever exceeds it, the CVEs kept are the recent
// ones relevant to current versions rather than ancient advisories.
const versionRangeCVELimit = 2000

// matchVersionRange queries CVEAffected + CVEAffectedVersion for candidates keyed
// by package name and ecosystem, then decides affected status per CVE using the
// CVE 5.1 precedence (exact > range > wildcard), per-product unaffected
// suppression, and lower-bound/segment-wildcard/changes[] handling. It also
// returns per-cveId affectedFacts for the alias-collated wildcard suppression in
// MatchDependency. The inner subquery bounds the candidate set to
// versionRangeCVELimit distinct CVEs (most-recently-published first); a CVE's
// version rows are never truncated mid-product because the outer query
// re-selects every row for the surviving cveIds.
// versionRangeEcoClauses builds the ecosystem-scoping predicate for the
// CVEAffected name match in two forms — aliased (`a.`-qualified, for the outer
// query) and bare (for the inner cveId subquery) — plus the positional args to
// append after $1 (dep.Name). Three regimes:
//
//	empty ecosystem      → "TRUE": name-only (unchanged behavior for callers that
//	                       don't carry an ecosystem, e.g. CPE-only lookups).
//	known ecosystem      → collectionURL = ANY(registry urls) OR vendor = ANY(vendors).
//	unmapped, non-empty  → legacy `collectionURL LIKE '%eco%'` so an exotic
//	                       ecosystem still matches rather than silently dropping.
func versionRangeEcoClauses(eco string) (outer, inner string, args []any) {
	if strings.TrimSpace(eco) == "" {
		return "TRUE", "TRUE", nil
	}
	if _, urls, vendors, ok := EcosystemEvidence(eco); ok {
		// Match the registry host case-insensitively and tolerate a trailing
		// slash or path suffix (e.g. "https://pypi.org/project/Django") — an
		// exact "= ANY(urls)" drops those otherwise-valid advisories.
		patterns := make([]string, len(urls))
		for i, u := range urls {
			patterns[i] = strings.ToLower(u) + "%"
		}
		outer = `(LOWER(a."collectionURL") LIKE ANY($2::text[]) OR LOWER(a."vendor") = ANY($3::text[]))`
		inner = `(LOWER(ai."collectionURL") LIKE ANY($2::text[]) OR LOWER(ai."vendor") = ANY($3::text[]))`
		return outer, inner, []any{patterns, vendors}
	}
	outer = `LOWER(a."collectionURL") LIKE '%' || LOWER($2) || '%'`
	inner = `LOWER(ai."collectionURL") LIKE '%' || LOWER($2) || '%'`
	return outer, inner, []any{eco}
}

// pep503Runs collapses runs of separators per PEP 503 name normalisation.
var pep503Runs = regexp.MustCompile(`[-_.]+`)

// normalizePypiName applies PEP 503: lowercase and collapse any run of
// `.`/`_`/`-` to a single `-`, so "zope.interface" and "zope-interface" match.
func normalizePypiName(name string) string {
	return pep503Runs.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// nameMatchExpr builds the package-name predicate for CVEAffected under the
// given table alias. For pypi it PEP 503-normalises both sides ($1 must be the
// pre-normalised name); for every other ecosystem it keeps a plain case-fold.
func nameMatchExpr(alias string, pypi bool) string {
	col := fmt.Sprintf(`COALESCE(%s."packageName", %s.product)`, alias, alias)
	if pypi {
		return fmt.Sprintf(`REGEXP_REPLACE(LOWER(%s), '[-_.]+', '-', 'g') = $1`, col)
	}
	return fmt.Sprintf(`LOWER(%s) = LOWER($1)`, col)
}

func matchVersionRange(ctx context.Context, q Querier, dep Dependency) ([]Match, map[string]affectedFacts, error) {
	if dep.Name == "" {
		return nil, nil, nil
	}

	// Ecosystem scoping. CVEAffected has no ecosystem column, so a name-only
	// match leaks across ecosystems (a pypi "foo" matching an npm "foo" advisory).
	// For a known ecosystem we constrain on the authoritative registry
	// collectionURL values + vendor names (EcosystemEvidence); empty ecosystem
	// stays name-only (unchanged contract for non-SCA callers); a non-empty but
	// unmapped ecosystem keeps the legacy substring gate so exotic ecosystems are
	// not silently dropped.
	outerEco, innerEco, ecoArgs := versionRangeEcoClauses(dep.Ecosystem)
	pypi := CanonicalEcosystem(dep.Ecosystem) == "pypi"
	name := dep.Name
	if pypi {
		name = normalizePypiName(dep.Name)
	}
	args := append([]any{name}, ecoArgs...)
	// The inner subquery bounds the candidate set to versionRangeCVELimit
	// distinct CVEs, ordered by most-recent publish date so a package with more
	// advisories than the cap keeps the CVEs relevant to current versions rather
	// than the lexicographically-first (oldest) ones. GROUP BY (not DISTINCT)
	// lets us ORDER BY MAX(datePublished); a CVE's version rows are still whole
	// because the outer query re-selects all rows for the surviving cveIds.
	rows, err := q.Query(ctx, fmt.Sprintf(`
		SELECT a."cveId", a.uuid, a.source, v.status, v."versionType",
		       v.version, v."lessThan", v."lessThanOrEqual", v."isValidVersion", v.changes
		FROM "CVEAffected" a
		JOIN "CVEMetadata" cm ON cm."cveId" = a."cveId" AND cm.source = a.source
		JOIN "CVEAffectedVersion" v ON v."affectedId" = a.uuid
		WHERE %s
		  AND (%s)
		  AND UPPER(COALESCE(cm.state, 'PUBLISHED')) NOT IN ('REJECTED', 'WITHDRAWN')
		  AND %s
		  AND a."cveId" IN (
		    SELECT ai."cveId" FROM "CVEAffected" ai
		    JOIN "CVEMetadata" cmi ON cmi."cveId" = ai."cveId" AND cmi.source = ai.source
		    WHERE %s
		      AND (%s)
		      AND UPPER(COALESCE(cmi.state, 'PUBLISHED')) NOT IN ('REJECTED', 'WITHDRAWN')
		      AND %s
		    GROUP BY ai."cveId"
		    ORDER BY MAX(cmi."datePublished") DESC NULLS LAST
		    LIMIT %d
		  )
		ORDER BY a."cveId", a.uuid`,
		nameMatchExpr("a", pypi), outerEco, notWithdrawnSQL(`a."cveId"`),
		nameMatchExpr("ai", pypi), innerEco, notWithdrawnSQL(`ai."cveId"`), versionRangeCVELimit),
		args...,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	perCve := map[string]*cveData{}
	var cveOrder []string
	facts := map[string]affectedFacts{}

	for rows.Next() {
		var cveID, affectedID, source, status string
		var versionType, versionValue, lessThan, lessThanOrEqual, changesRaw *string
		var isValidVersion *bool
		if err := rows.Scan(&cveID, &affectedID, &source, &status, &versionType,
			&versionValue, &lessThan, &lessThanOrEqual, &isValidVersion, &changesRaw); err != nil {
			continue
		}
		// Skip rows the normaliser marked invalid (before recording any fact).
		// Defensive only in practice: the go-processor importer
		// (vdb-manager/.../internal/version/parser.go) always writes Valid=true
		// (unrecoverable inputs collapse to the "*" sentinel, not an invalid
		// flag), so this guards against legacy/other importers rather than the
		// main pipeline. It does NOT drop django versions.
		if isValidVersion != nil && !*isValidVersion {
			continue
		}

		cd := perCve[cveID]
		if cd == nil {
			cd = &cveData{source: source, products: map[string][]affRow{}}
			perCve[cveID] = cd
			cveOrder = append(cveOrder, cveID)
		}
		vt := derefStr(versionType)
		if vt == "" {
			vt = dep.Ecosystem
		}
		row := affRow{
			status:          strings.ToLower(strings.TrimSpace(status)),
			versionType:     vt,
			version:         derefStr(versionValue),
			lessThan:        derefStr(lessThan),
			lessThanOrEqual: derefStr(lessThanOrEqual),
			changes:         parseChanges(changesRaw),
		}
		if _, ok := cd.products[affectedID]; !ok {
			cd.productOrder = append(cd.productOrder, affectedID)
		}
		cd.products[affectedID] = append(cd.products[affectedID], row)

		// Record facts from every AFFECTED row (matched or not) for suppression.
		if row.status == "affected" {
			f := facts[cveID]
			if rowIsWildcard(row) || rowIsZeroPlaceholder(row) {
				f.hasWildcard = true
				if rowIsOpenRange(row) {
					f.hasOpenRange = true
				}
			} else if row.version != "" || row.lessThan != "" || row.lessThanOrEqual != "" {
				f.hasSpecific = true
				if row.lessThan != "" || row.lessThanOrEqual != "" {
					f.hasBounded = true
				}
			}
			facts[cveID] = f
		}
	}

	var matches []Match
	for _, cveID := range cveOrder {
		cd := perCve[cveID]
		dropSupersededZeroRows(cd)
		verdict, method, rangeStr := evaluateCVE(dep.Version, dep.Ecosystem, cd)
		if verdict == cveDrop {
			continue
		}
		src := cd.source
		if src == "" {
			src = "CVEAffected"
		}
		m := Match{CveID: cveID, Source: src, Method: method, VulnerableRange: rangeStr}
		switch verdict {
		case cveSpecific:
			m.isSpecific = true
		case cveWildcard:
			m.isWildcard = true
		case cveUnknown:
			m.isCoarse = true
		}
		matches = append(matches, m)
	}
	return matches, facts, nil
}

// cveVerdict is the combined per-CVE outcome across its products.
type cveVerdict int

const (
	cveDrop     cveVerdict = iota // every product with data agrees: unaffected
	cveUnknown                    // inconclusive — kept conservatively (coarse)
	cveWildcard                   // affected via "*" (all versions)
	cveSpecific                   // affected via an exact/range/segment match
)

// evaluateCVE folds the per-product verdicts into one CVE verdict, mirroring
// vdb-api's discoverCvesForPurl rule: any affected product wins; a CVE is
// dropped only when every product with version data decisively agrees the
// installed version is unaffected; inconclusive data is kept (as coarse).
func evaluateCVE(installed, eco string, cd *cveData) (cveVerdict, string, string) {
	var specificMethod, specificRange string
	haveSpecific, haveWildcard, sawUnaffected, sawNone := false, false, false, false

	for _, pid := range cd.productOrder {
		pv, method, rng := evaluateProduct(installed, eco, cd.products[pid])
		switch pv {
		case prodSpecific:
			if !haveSpecific {
				haveSpecific, specificMethod, specificRange = true, method, rng
			}
		case prodWildcard:
			haveWildcard = true
		case prodUnaffected:
			sawUnaffected = true
		case prodNone:
			sawNone = true
		}
	}

	switch {
	case haveSpecific:
		return cveSpecific, specificMethod, specificRange
	case haveWildcard:
		return cveWildcard, "version-range:wildcard", "*"
	case sawUnaffected && !sawNone:
		return cveDrop, "", ""
	default:
		return cveUnknown, "version-range:unknown", ""
	}
}

// prodVerdict is the outcome for one CVEAffected product (affectedId).
type prodVerdict int

const (
	prodNone       prodVerdict = iota // had data, installed matched nothing
	prodUnaffected                    // installed decisively unaffected
	prodWildcard                      // affected via "*"
	prodSpecific                      // affected via exact/range/segment
)

// evaluateProduct applies the CVE 5.1 precedence to one product's rows:
// exact-unaffected > exact-affected > range-unaffected > range-affected >
// wildcard-affected > none.
func evaluateProduct(installed, eco string, rows []affRow) (prodVerdict, string, string) {
	var exactAffMethod, exactAffRange string
	var rangeAffMethod, rangeAffRange string
	haveExactUnaff, haveExactAff := false, false
	haveRangeUnaff, haveRangeAff := false, false
	haveWildcardAff := false

	for _, r := range rows {
		if rowIsWildcard(r) {
			if r.status == "affected" {
				haveWildcardAff = true
			}
			continue
		}
		isRange := r.lessThan != "" || r.lessThanOrEqual != ""

		if !isRange {
			// Exact entry (version only).
			if r.version == "" || !exactMatches(installed, r.versionType, r.version) {
				continue
			}
			switch r.status {
			case "unaffected":
				haveExactUnaff = true
			case "affected":
				if !haveExactAff {
					haveExactAff = true
					exactAffMethod = exactMethod(r.version)
					exactAffRange = "=" + r.version
				}
			}
			continue
		}

		// Range entry: lower bound = version (zero ⇒ unbounded), gated.
		lower := r.version
		if isZeroVer(lower) {
			lower = ""
		}
		inRange, _ := ver.Within(eco, r.versionType, installed, lower, r.lessThan, r.lessThanOrEqual)
		if !inRange {
			continue
		}
		switch effectiveRowStatus(installed, eco, r) {
		case "unaffected":
			haveRangeUnaff = true
		case "affected":
			if !haveRangeAff {
				haveRangeAff = true
				if r.lessThan != "" {
					rangeAffMethod = "version-range:lessThan"
				} else {
					rangeAffMethod = "version-range:lessThanOrEqual"
				}
				rangeAffRange = buildRangeString(ptrOrNil(r.version), ptrOrNil(r.lessThan), ptrOrNil(r.lessThanOrEqual))
			}
		}
	}

	switch {
	case haveExactUnaff:
		return prodUnaffected, "", ""
	case haveExactAff:
		return prodSpecific, exactAffMethod, exactAffRange
	case haveRangeUnaff:
		return prodUnaffected, "", ""
	case haveRangeAff:
		return prodSpecific, rangeAffMethod, rangeAffRange
	case haveWildcardAff:
		return prodWildcard, "version-range:wildcard", "*"
	default:
		return prodNone, "", ""
	}
}

// rowIsWildcard reports whether a row encodes an "all versions" signal.
// rowIsZeroPlaceholder reports an affected row that says only "from the beginning":
// an exact version 0 with no bound. CVE 5 sources write it for "introduced 0" when
// the fix is unknown or unstated, and no release is version 0. It is the same claim as
// an open range, not a specific version, so it must not count as the specific
// evidence that discards an alias group's real open-ended range: a bare `0` from
// cve.org used to suppress `introduced 0, never fixed` from OSV/GitHub for the same
// advisory, and the vulnerable version went unreported.
func rowIsZeroPlaceholder(r affRow) bool {
	if r.lessThan != "" || r.lessThanOrEqual != "" {
		return false
	}
	switch strings.TrimSpace(r.version) {
	case "0", "0.0", "0.0.0", "0.0.0.0":
		return true
	}
	return false
}

// rowIsOpenRange reports "introduced X, never fixed": a concrete start with lessThan "*".
// A bare "*" version is a different, weaker claim (every version, no start stated).
func rowIsOpenRange(r affRow) bool {
	return ver.IsFullWildcard(r.lessThan) && r.version != "" && !ver.IsFullWildcard(r.version)
}

func rowIsWildcard(r affRow) bool {
	return ver.IsFullWildcard(r.version) ||
		ver.IsFullWildcard(r.lessThan) ||
		ver.IsFullWildcard(r.lessThanOrEqual)
}

// exactMatches reports whether installed satisfies an exact / segment-wildcard
// affected version, falling back to string equality when unparseable.
func exactMatches(installed, versionType, version string) bool {
	if m, isSeg := ver.MatchSegmentWildcard(installed, version); isSeg {
		return m
	}
	if cmp, ok := ver.Compare("", versionType, installed, version); ok {
		return cmp == 0
	}
	return installed == version
}

func exactMethod(version string) string {
	if ver.IsSegmentWildcard(version) {
		return "version-range:segwild"
	}
	return "version-range:exact"
}

// effectiveRowStatus applies CVE 5.1 changes[]: the status of the latest change
// whose At is <= installed wins; otherwise the row's own status.
func effectiveRowStatus(installed, eco string, r affRow) string {
	result := r.status
	bestAt := ""
	for _, ch := range r.changes {
		cmp, ok := ver.Compare(eco, r.versionType, installed, ch.at)
		if !ok || cmp < 0 {
			continue
		}
		st := strings.ToLower(strings.TrimSpace(ch.status))
		if st != "affected" && st != "unaffected" {
			continue
		}
		if bestAt == "" {
			bestAt, result = ch.at, st
			continue
		}
		if c2, ok2 := ver.Compare(eco, r.versionType, ch.at, bestAt); ok2 && c2 > 0 {
			bestAt, result = ch.at, st
		}
	}
	return result
}

// isZeroVer reports whether s is an all-zero version ("0", "0.0.0") — treated as
// an unbounded lower bound so prereleases of 0 are included.
func isZeroVer(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if s == "" {
		return false
	}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '+' }) {
		for _, c := range p {
			if c != '0' {
				return false
			}
		}
	}
	return true
}

func buildRangeString(versionValue, lessThan, lessThanOrEqual *string) string {
	parts := []string{}
	if versionValue != nil && *versionValue != "" && !ver.IsFullWildcard(*versionValue) && !isZeroVer(*versionValue) {
		parts = append(parts, ">="+*versionValue)
	}
	if lessThan != nil && *lessThan != "" {
		parts = append(parts, "<"+*lessThan)
	}
	if lessThanOrEqual != nil && *lessThanOrEqual != "" {
		parts = append(parts, "<="+*lessThanOrEqual)
	}
	return strings.Join(parts, ", ")
}

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseChanges decodes the CVEAffectedVersion.changes JSON text column
// (CVE 5.1 [{at, status}] steps). Junk yields nil.
func parseChanges(raw *string) []verChange {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil
	}
	var arr []map[string]any
	if json.Unmarshal([]byte(*raw), &arr) != nil {
		return nil
	}
	var out []verChange
	for _, m := range arr {
		at, _ := m["at"].(string)
		status, _ := m["status"].(string)
		if at == "" || status == "" {
			continue
		}
		out = append(out, verChange{at: at, status: status})
	}
	return out
}
