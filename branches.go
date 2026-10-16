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
	loA, hiA, cA, okA := envelope(a, eco)
	loB, hiB, cB, okB := envelope(b, eco)
	if !okA || !okB {
		return false
	}
	return loA == loB && sameEnd(hiA, cA, hiB, cB)
}

// sameEnd reports that two range ends are one end: the same version (whether the source
// wrote it as inclusive or exclusive, since a CNA that writes `<= 3.2.2` for a release the
// ecosystem sources fix at 3.2.2 is making the common off-by-one), or the same first
// release outside the range once an inclusive bound is read as `< next`.
func sameEnd(rawA, canonA, rawB, canonB string) bool {
	return rawA == rawB || canonA == canonB
}

// envelope returns the lowest start and highest end, as the version strings that carry them.
func envelope(rs []factRange, eco string) (lo, hi, canonHi string, ok bool) {
	first := true
	var rawHi string
	for _, r := range rs {
		raw := r.lt
		if raw == "" {
			raw = r.lte
		}
		canon, _ := canonicalUpper(r.lt, r.lte)
		if raw == "" || raw == "*" {
			return "", "", "", false
		}
		start := r.lower
		if first {
			lo, rawHi, canonHi, first = start, raw, canon, false
			continue
		}
		if c, ok := ver.Compare(eco, r.vt, start, lo); ok && c < 0 {
			lo = start
		}
		if c, ok := ver.Compare(eco, r.vt, raw, rawHi); ok && c > 0 {
			rawHi = raw
		}
		if c, ok := ver.Compare(eco, r.vt, canon, canonHi); ok && c > 0 {
			canonHi = canon
		}
	}
	return lo, rawHi, canonHi, !first
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
	if len(by) < 1 {
		return
	}
	filled := func(x factRange) bool {
		if !rangesContain([]factRange{x}, installed, eco) {
			return false
		}
		xRaw := x.lt
		if xRaw == "" {
			xRaw = x.lte
		}
		xCanon, _ := canonicalUpper(x.lt, x.lte)
		for src, t := range by {
			rows := t.rows
			if src == x.src {
				// The same source may state the envelope and the branches (cve.org lists
				// brace-expansion as `0 .. <= 5.0.7` beside `0 .. < 1.1.17`,
				// `2.0.0 .. < 2.1.3`, ...). The envelope row is then the summary of the
				// branches, not a second claim, so judge it against the rows that are not
				// the envelope itself.
				rows = nil
				for _, o := range t.rows {
					oRaw := o.lt
					if oRaw == "" {
						oRaw = o.lte
					}
					oCanon, _ := canonicalUpper(o.lt, o.lte)
					if o.lower == x.lower && sameEnd(xRaw, xCanon, oRaw, oCanon) {
						continue
					}
					rows = append(rows, o)
				}
			}
			if len(rows) < 2 || rangesContain(rows, installed, eco) {
				continue
			}
			lo, hi, canonHi, ok := envelope(rows, eco)
			if ok && lo == x.lower && sameEnd(xRaw, xCanon, hi, canonHi) {
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
