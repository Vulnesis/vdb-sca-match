package match

import ver "github.com/Vulnetix/vdb-sca-match/version"

// applyFinerBranchRanges drops a match whose range lumps several branches together when
// another id of the same alias group describes the same span branch by branch and the
// installed version falls in one of its gaps.
//
// cve.org states next's CVE-2026-27980 as one range, `>= 10.0.0, < 16.1.7`. GitHub states
// it as `>= 10.0.0, < 15.5.14` and `>= 16.0.0-beta.0, < 16.1.7`: 15.x was fixed by a
// backport at 15.5.14, and 15.5.15 is past it. Unioned, the coarse range flagged a release
// the advisory itself fixed, which is the "advisory says fixed in X, table says vulnerable"
// report.
//
// The signal is deliberately narrow: the finer id must have more ranges, and both ids must
// span the same envelope (the same lowest start and the same highest end). Two sources
// describing one span, one with a gap in it, is a backport; a source that merely knows less
// does not have that shape.
func applyFinerBranchRanges(seen map[string]Match, facts map[string]affectedFacts, groupOf map[string]string, installed, eco string) {
	if installed == "" {
		return
	}
	groupKey := func(id string) string {
		if groupOf != nil {
			if g, ok := groupOf[id]; ok {
				return g
			}
		}
		return id
	}
	byGroup := map[string][]string{}
	for id := range facts {
		g := groupKey(id)
		byGroup[g] = append(byGroup[g], id)
	}
	for id := range seen {
		x := facts[id]
		if len(x.ranges) == 0 || !rangesContain(x.ranges, installed, eco) {
			continue
		}
		for _, other := range byGroup[groupKey(id)] {
			if other == id {
				continue
			}
			y := facts[other]
			if len(y.ranges) <= len(x.ranges) || rangesContain(y.ranges, installed, eco) {
				continue
			}
			if sameEnvelope(x.ranges, y.ranges, eco) {
				delete(seen, id)
				break
			}
		}
	}
}

// rangesContain reports whether installed falls inside any of the ranges.
func rangesContain(rs []factRange, installed, eco string) bool {
	for _, r := range rs {
		lower := r.lower
		if lower == "0" {
			lower = ""
		}
		if in, ok := ver.Within(eco, r.vt, installed, lower, r.lt, r.lte); ok && in {
			return true
		}
	}
	return false
}

// sameEnvelope reports that both range sets start at the same lowest version and end at
// the same highest one.
func sameEnvelope(a, b []factRange, eco string) bool {
	loA, hiA, okA := envelope(a, eco)
	loB, hiB, okB := envelope(b, eco)
	if !okA || !okB {
		return false
	}
	return loA == loB && hiA == hiB
}

// envelope returns the lowest start and highest end, as the version strings that carry them.
func envelope(rs []factRange, eco string) (lo, hi string, ok bool) {
	first := true
	for _, r := range rs {
		upper := r.lt
		if upper == "" {
			upper = r.lte
		}
		if upper == "" || upper == "*" {
			return "", "", false
		}
		start := r.lower
		if first {
			lo, hi, first = start, upper, false
			continue
		}
		if c, ok := ver.Compare(eco, r.vt, start, lo); ok && c < 0 {
			lo = start
		}
		if c, ok := ver.Compare(eco, r.vt, upper, hi); ok && c > 0 {
			hi = upper
		}
	}
	return lo, hi, !first
}

// dropEnvelopeFill removes, within one CVE, a single range that spans the whole of what
// another source states branch by branch, when the installed version sits in a gap
// between those branches.
//
// next's CVE-2026-27980 carries `10.0.0 .. < 15.5.14` and `16.0.0-beta.0 .. < 16.1.7` from
// cve.org, GitHub, CIRCL and GitLab, and ALSO `10.0.0 .. < 16.1.7` from GitLab: the
// envelope of the other two, filling the gap where 15.x was fixed by a backport. It flagged
// 15.5.15, a release the advisory itself fixed.
func dropEnvelopeFill(cd *cveData, installed, eco string) {
	if installed == "" {
		return
	}
	type srcRows struct {
		rows []factRange
	}
	by := map[string]*srcRows{}
	for _, rows := range cd.products {
		for _, r := range rows {
			if r.status != "affected" || rowIsWildcard(r) || (r.lessThan == "" && r.lessThanOrEqual == "") {
				continue
			}
			if by[r.src] == nil {
				by[r.src] = &srcRows{}
			}
			by[r.src].rows = append(by[r.src].rows, factRange{lower: r.version, lt: r.lessThan, lte: r.lessThanOrEqual, vt: r.versionType, src: r.src})
		}
	}
	if len(by) < 2 {
		return
	}
	filled := func(x factRange) bool {
		if !rangesContain([]factRange{x}, installed, eco) {
			return false
		}
		for src, t := range by {
			if src == x.src || len(t.rows) < 2 || rangesContain(t.rows, installed, eco) {
				continue
			}
			lo, hi, ok := envelope(t.rows, eco)
			upper := x.lt
			if upper == "" {
				upper = x.lte
			}
			if ok && lo == x.lower && hi == upper {
				return true
			}
		}
		return false
	}
	for pid, rows := range cd.products {
		kept := rows[:0:0]
		for _, r := range rows {
			if r.status == "affected" && !rowIsWildcard(r) && (r.lessThan != "" || r.lessThanOrEqual != "") &&
				filled(factRange{lower: r.version, lt: r.lessThan, lte: r.lessThanOrEqual, vt: r.versionType, src: r.src}) {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			delete(cd.products, pid)
		} else {
			cd.products[pid] = kept
		}
	}
	order := cd.productOrder[:0:0]
	for _, pid := range cd.productOrder {
		if _, ok := cd.products[pid]; ok {
			order = append(order, pid)
		}
	}
	cd.productOrder = order
}
