package sarif

import "strings"

// ToolInfo is the attribution a run carries: who produced these findings.
type ToolInfo struct {
	Name           string
	Version        string
	Organization   string
	InformationURI string
}

// ToolOf extracts the attribution from a run's driver. SemanticVersion is
// preferred over Version when both are present because it is the one tools
// promise to keep parseable.
func ToolOf(run Run) ToolInfo {
	d := run.Tool.Driver
	version := strings.TrimSpace(d.SemanticVersion)
	if version == "" {
		version = strings.TrimSpace(d.Version)
	}
	name := strings.TrimSpace(d.Name)
	if name == "" {
		name = strings.TrimSpace(d.FullName)
	}
	return ToolInfo{
		Name:           name,
		Version:        version,
		Organization:   strings.TrimSpace(d.Organization),
		InformationURI: strings.TrimSpace(d.InformationURI),
	}
}

// resolveRule finds the ReportingDescriptor a result refers to.
//
// Precedence follows the spec: an explicit rule reference (which may select an
// extension's rule set) beats ruleIndex into the driver, which beats a linear
// scan by id across the driver and every extension. Every index is bounds
// checked — an out-of-range index yields nil plus a diagnostic from the caller,
// never a silently wrong rule.
func resolveRule(run *Run, res *Result) (*ReportingDescriptor, bool) {
	if run == nil || res == nil {
		return nil, true
	}

	if res.Rule != nil {
		comp := resolveToolComponent(run, res.Rule.ToolComponent)
		if res.Rule.Index != nil {
			i := *res.Rule.Index
			if i < 0 || comp == nil || i >= len(comp.Rules) {
				return nil, false
			}
			return &comp.Rules[i], true
		}
		if res.Rule.ID != "" {
			if r := findRuleByID(run, res.Rule.ID); r != nil {
				return r, true
			}
		}
	}

	if res.RuleIndex != nil {
		i := *res.RuleIndex
		// -1 is the spec's "absent" sentinel; treat it as no index at all.
		if i >= 0 {
			rules := run.Tool.Driver.Rules
			if i >= len(rules) {
				return nil, false
			}
			return &rules[i], true
		}
	}

	if res.RuleID != "" {
		if r := findRuleByID(run, res.RuleID); r != nil {
			return r, true
		}
	}
	return nil, true
}

// resolveToolComponent selects the driver (absent reference, or index -1) or an
// extension by index/name/guid.
func resolveToolComponent(run *Run, ref *ToolComponentReference) *ToolComponent {
	if run == nil {
		return nil
	}
	if ref == nil {
		return &run.Tool.Driver
	}
	if ref.Index != nil {
		i := *ref.Index
		if i < 0 {
			return &run.Tool.Driver
		}
		if i < len(run.Tool.Extensions) {
			return &run.Tool.Extensions[i]
		}
		return nil
	}
	if ref.Name != "" {
		if strings.EqualFold(run.Tool.Driver.Name, ref.Name) {
			return &run.Tool.Driver
		}
		for i := range run.Tool.Extensions {
			if strings.EqualFold(run.Tool.Extensions[i].Name, ref.Name) {
				return &run.Tool.Extensions[i]
			}
		}
		return nil
	}
	if ref.GUID != "" {
		if strings.EqualFold(run.Tool.Driver.GUID, ref.GUID) {
			return &run.Tool.Driver
		}
		for i := range run.Tool.Extensions {
			if strings.EqualFold(run.Tool.Extensions[i].GUID, ref.GUID) {
				return &run.Tool.Extensions[i]
			}
		}
		return nil
	}
	return &run.Tool.Driver
}

// findRuleByID scans the driver then every extension for a rule with this id.
func findRuleByID(run *Run, id string) *ReportingDescriptor {
	for i := range run.Tool.Driver.Rules {
		if run.Tool.Driver.Rules[i].ID == id {
			return &run.Tool.Driver.Rules[i]
		}
	}
	for e := range run.Tool.Extensions {
		rules := run.Tool.Extensions[e].Rules
		for i := range rules {
			if rules[i].ID == id {
				return &rules[i]
			}
		}
	}
	return nil
}

// countRules totals the rule descriptors across the driver and its extensions.
func countRules(run *Run) int {
	if run == nil {
		return 0
	}
	n := len(run.Tool.Driver.Rules)
	for i := range run.Tool.Extensions {
		n += len(run.Tool.Extensions[i].Rules)
	}
	return n
}
