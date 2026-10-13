package match

import (
	"context"
)

// matchPurl queries PackageVersionCVE for registry-precise matches.
func matchPurl(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	if dep.Purl == "" {
		return nil, nil
	}

	eco, fullName, version := ParsePurl(dep.Purl)
	if eco == "" || fullName == "" {
		return nil, nil
	}

	rows, err := q.Query(ctx, `
		SELECT pvc."cveId"
		FROM "PackageVersionCVE" pvc
		JOIN "PackageVersion" pv ON pv.uuid = pvc."packageVersionId"
		WHERE LOWER(pv.ecosystem) = LOWER($1)
		  AND LOWER(pv."packageName") = LOWER($2)
		  AND ($3 = '' OR pv.version = $3)
		  AND pvc."relationshipType" IN ('affects','vulnerable')
		  AND EXISTS (
		    SELECT 1 FROM "CVEMetadata" cm
		    WHERE cm."cveId" = pvc."cveId"
		      AND UPPER(COALESCE(cm.state, 'PUBLISHED')) NOT IN ('REJECTED', 'WITHDRAWN')
		  )
		  AND `+notWithdrawnSQL(`pvc."cveId"`)+`
		LIMIT 2000`,
		eco, fullName, version,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// A versioned PURL match is registry-exact (specific, never suppressed); a
	// version-less PURL matches every row for the package, so it is coarse.
	method, coarse, specific := "purl", false, true
	if version == "" {
		method, coarse, specific = "purl:coarse", true, false
	}

	var matches []Match
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		matches = append(matches, Match{
			CveID:      cveID,
			Source:     "PackageVersionCVE",
			Method:     method,
			isCoarse:   coarse,
			isSpecific: specific,
		})
	}
	return matches, nil
}
