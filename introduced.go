package match

import "strings"

// dropSupersededZeroRows removes "introduced 0" ranges that another record of the
// same advisory states more precisely.
//
// CVE 5 and GitLab write a range with no stated start as version 0, so
// CVE-2024-43788 is `0 .. < 5.94.0` there, while GitHub and OSV, which work out
// where the bug entered, write `5.0.0-alpha.0 .. < 5.94.0`. The two share one fix;
// they differ in where the vulnerable code began. Unioned, the looser one flagged
// webpack 1.15.0, a release that predates the code, and the same happened to tar
// 2.2.1, node-fetch 1.7 and a long tail of old majors. The range with a real start
// is the stronger statement, so it replaces the zero-start one that ends at the
// same fix. A zero-start range with no counterpart is left alone: it is all the
// evidence there is.
func dropSupersededZeroRows(cd *cveData) {
	precise := map[string]bool{}
	for _, rows := range cd.products {
		for _, r := range rows {
			if k := upperKey(r); k != "" && r.status == "affected" && !rowIsZeroStart(r) && !rowIsWildcard(r) && strings.TrimSpace(r.version) != "" {
				precise[k] = true
			}
		}
	}
	if len(precise) == 0 {
		return
	}
	for pid, rows := range cd.products {
		kept := rows[:0:0]
		for _, r := range rows {
			if r.status == "affected" && rowIsZeroStart(r) && precise[upperKey(r)] {
				continue
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
	switch {
	case strings.TrimSpace(r.lessThan) != "":
		return "lt:" + strings.TrimSpace(r.lessThan)
	case strings.TrimSpace(r.lessThanOrEqual) != "":
		return "lte:" + strings.TrimSpace(r.lessThanOrEqual)
	}
	return ""
}
