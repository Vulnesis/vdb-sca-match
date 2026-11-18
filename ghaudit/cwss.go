package ghaudit

import "github.com/Vulnesis/vdb-sca-match/cwss"

// CWSS returns the finding's CWSS vector and 0..10 score. When facts left the
// severity where the rule declared it, that is the rule's own vector; when they
// moved it, the vector is derived at the adjusted severity, so a finding the
// repository's settings defuse scores lower than the same flaw left open.
func (f *Finding) CWSS(r *Rule) (string, float64) {
	if r != nil && r.CWSS != "" && f.Severity == r.Severity {
		if m, err := cwss.Parse(r.CWSS); err == nil {
			return m.Vector(), m.Score()
		}
	}
	var cwes []int
	var tags []string
	if r != nil {
		cwes, tags = r.CWE, r.Tags
	}
	m := cwss.Derive(cwss.Input{Severity: string(f.Severity), CWEs: cwes, Tags: tags, Kind: "iac", Reach: cwss.ReachRemote})
	return m.Vector(), m.Score()
}
