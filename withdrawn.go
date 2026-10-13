package match

// notWithdrawnSQL returns a predicate that is false for an advisory its own
// publisher has withdrawn.
//
// CVEMetadata holds one row per (id, source). The per-row state filter alone
// leaves a withdrawn GHSA / PYSEC / GO advisory reportable: GitHub and OSV mark
// the record REJECTED, but a mirror (gitlab, google_osi) keeps its stale
// PUBLISHED copy, and that copy still carries the package's affected rows.
// For an identifier that is not a CVE, a withdrawal recorded by any source
// withdraws it. A CVE is excluded: cve.org is its authority, and a mirror
// rejecting a CVE that cve.org publishes must not hide a real vulnerability.
//
// idExpr is the SQL expression holding the advisory id (e.g. `a."cveId"`).
func notWithdrawnSQL(idExpr string) string {
	return `(UPPER(` + idExpr + `) LIKE 'CVE-%' OR NOT EXISTS (
		    SELECT 1 FROM "CVEMetadata" wd
		    WHERE wd."cveId" = ` + idExpr + `
		      AND UPPER(COALESCE(wd.state, 'PUBLISHED')) IN ('REJECTED', 'WITHDRAWN')))`
}
