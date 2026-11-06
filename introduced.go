package match

import (
	"strconv"
	"strings"
)

// dropSupersededZeroRows removes an "introduced 0" range that a DIFFERENT source states
// more precisely.
//
// CVE 5 and GitLab write a range with no stated start as version 0, so
// CVE-2024-43788 is `0 .. < 5.94.0` there, while GitHub and OSV, which work out
// where the bug entered, write `5.0.0-alpha.0 .. < 5.94.0`. The two share one fix;
// they differ in where the vulnerable code began. Unioned, the looser one flagged
// webpack 1.15.0, a release that predates the code. The range with a real start is
// the stronger statement, so it replaces the zero-start one that ends at the same fix.
//
// Only across sources. A source that states BOTH `0 .. < X` and `S .. < X` itself (cve.org
// lists uuid as `0 .. < 11.1.1` and `11.0.0 .. < 11.1.1`) is stating the union, not
// correcting itself: GitHub agrees with `< 11.1.1`, and dropping the zero-start row hid
// uuid 2.0.3. A zero-start range with no counterpart is left alone: it is all the evidence
// there is.
func dropSupersededZeroRows(cd *cveData) {
	zeroBySource := map[string]bool{} // source|upper -> that source states a zero-start range ending there
	for _, rows := range cd.products {
		for _, r := range rows {
			if r.status == "affected" && rowIsZeroStart(r) {
				zeroBySource[r.src+"|"+upperKey(r)] = true
			}
		}
	}
	// precise[upper] = the sources whose precise range ends there and who do not also
	// state a zero-start range there.
	precise := map[string]map[string]bool{}
	for _, rows := range cd.products {
		for _, r := range rows {
			k := upperKey(r)
			if k == "" || r.status != "affected" || rowIsZeroStart(r) || rowIsWildcard(r) || strings.TrimSpace(r.version) == "" {
				continue
			}
			if zeroBySource[r.src+"|"+k] {
				continue
			}
			if precise[k] == nil {
				precise[k] = map[string]bool{}
			}
			precise[k][r.src] = true
		}
	}
	if len(precise) == 0 {
		return
	}
	for pid, rows := range cd.products {
		kept := rows[:0:0]
		for _, r := range rows {
			if r.status == "affected" && rowIsZeroStart(r) {
				if by := precise[upperKey(r)]; len(by) > 0 && (len(by) != 1 || !by[r.src]) {
					continue
				}
			}
			kept = append(kept, r)
		}
		if len(kept) == len(rows) {
			continue
		}
		if len(kept) == 0 {
			delete(cd.products, pid)
			continue
		}
		cd.products[pid] = kept
	}
	order := cd.productOrder[:0:0]
	for _, pid := range cd.productOrder {
		if _, ok := cd.products[pid]; ok {
			order = append(order, pid)
		}
	}
	cd.productOrder = order
}

// rowIsZeroStart reports a bounded range whose start is the "from the beginning"
// placeholder: version 0 with a real upper bound.
func rowIsZeroStart(r affRow) bool {
	if r.lessThan == "" && r.lessThanOrEqual == "" {
		return false
	}
	if rowIsWildcard(r) {
		return false
	}
	switch strings.TrimSpace(r.version) {
	case "0", "0.0", "0.0.0", "0.0.0.0":
		return true
	}
	return false
}

// upperKey names a range's end: the fix it stops at. Empty when it has none.
func upperKey(r affRow) string {
	u, exclusive := canonicalUpper(r.lessThan, r.lessThanOrEqual)
	switch {
	case u == "":
		return ""
	case exclusive:
		return "lt:" + u
	}
	return "lte:" + u
}

// nextRelease names the release a patch-level inclusive bound stops just before:
// `<= 4.1.1` and `< 4.1.2` are one statement written two ways, and sources disagree on
// which they use (GitLab, cve.org and NVD write the inclusive last affected release;
// GitHub and OSV write the first fixed one). Only a plain dotted-numeric version has a
// successor this can name; anything else (a pre-release, a suffix, a date) returns false
// and is compared as written.
func nextRelease(v string) (string, bool) {
	v = strings.TrimSpace(v)
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return "", false
	}
	for _, p := range parts {
		if p == "" || len(p) > 9 {
			return "", false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", false
			}
		}
	}
	n := 0
	for _, c := range parts[len(parts)-1] {
		n = n*10 + int(c-'0')
	}
	parts[len(parts)-1] = strconv.Itoa(n + 1)
	return strings.Join(parts, "."), true
}

// canonicalUpper is a range's end as the first release outside it, so an inclusive and an
// exclusive spelling of one end compare equal. The second result is true when the bound is
// exclusive after the rewrite.
func canonicalUpper(lt, lte string) (string, bool) {
	if v := strings.TrimSpace(lt); v != "" {
		return v, true
	}
	if v := strings.TrimSpace(lte); v != "" {
		if next, ok := nextRelease(v); ok {
			return next, true
		}
		return v, false
	}
	return "", false
}
