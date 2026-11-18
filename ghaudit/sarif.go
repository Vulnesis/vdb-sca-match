package ghaudit

import (
	"strconv"
	"strings"

	"github.com/Vulnesis/vdb-sca-match/sarif"
)

// ToolName is the SARIF driver name, and the ScannerRun.toolName the
// platform files these results under (category IAC, with the other
// misconfigurations).
const ToolName = "Vulnesis GitHub"

// securitySeverity is GitHub code scanning's numeric scale, which the SARIF
// decomposer reads before level.
func securitySeverity(s Severity) string {
	switch s {
	case Critical:
		return "9.5"
	case High:
		return "8.0"
	case Medium:
		return "5.5"
	case Low:
		return "3.0"
	}
	return "0.0"
}

// RuleMarkdown is the rule's full help text, also used for Finding
// descriptions so the console renders the same text a SARIF viewer would.
func RuleMarkdown(r *Rule) string {
	var b strings.Builder
	b.WriteString(r.Description)
	b.WriteString("\n\n**Remediation**\n\n")
	b.WriteString(r.Remediation)
	if len(r.Requires) > 0 || len(r.Enhances) > 0 {
		b.WriteString("\n\n**Context used**\n\n")
		for _, g := range append(append([]string{}, r.Requires...), r.Enhances...) {
			b.WriteString("- " + strings.ReplaceAll(g, "_", " ") + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// SARIFOptions controls run-level metadata.
type SARIFOptions struct {
	ToolVersion   string
	RepositoryURI string
	Branch        string
	Revision      string
}

// SARIF renders a report as a SARIF 2.1.0 log with one run.
func (rep *Report) SARIF(opt SARIFOptions) *sarif.Log {
	rules := make([]sarif.ReportingDescriptor, 0, len(rep.Rules))
	index := map[string]int{}
	for i, r := range rep.Rules {
		index[r.ID] = i
		cwes := make([]string, len(r.CWE))
		for k, c := range r.CWE {
			cwes[k] = "CWE-" + strconv.Itoa(c)
		}
		props := sarif.PropertyBag{
			"severity":          string(r.Severity),
			"security-severity": securitySeverity(r.Severity),
			"precision":         precision(r.Confidence),
			"tags":              append(append([]string{}, r.Tags...), cwes...),
			"vulnetix/kind":     "iac",
			"vulnetix/task":     string(r.Task),
		}
		if len(cwes) > 0 {
			props["cwe"] = cwes
		}
		if len(r.CAPEC) > 0 {
			props["capec"] = r.CAPEC
		}
		if len(r.ATTACK) > 0 {
			props["attack_technique"] = r.ATTACK
		}
		if r.CWSS != "" {
			props["cwss"] = r.CWSS
		}
		if len(r.Requires) > 0 {
			props["vulnetix/requires"] = r.Requires
		}
		rules = append(rules, sarif.ReportingDescriptor{
			ID:                   r.ID,
			Name:                 r.Name,
			ShortDescription:     &sarif.Message{Text: r.Summary},
			FullDescription:      &sarif.Message{Text: r.Description},
			Help:                 &sarif.Message{Text: r.Description + "\n\nRemediation: " + r.Remediation, Markdown: RuleMarkdown(r)},
			HelpURI:              r.HelpURI(),
			DefaultConfiguration: &sarif.ReportingConfiguration{Level: sarif.LevelFromSeverity(string(r.Severity))},
			Properties:           props,
		})
	}

	results := make([]sarif.Result, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		idx := index[f.RuleID]
		res := sarif.Result{
			RuleID:       f.RuleID,
			RuleIndex:    &idx,
			Level:        sarif.LevelFromSeverity(string(f.Severity)),
			Message:      sarif.Message{Text: f.Message},
			Fingerprints: map[string]string{"vulnetix/v1": f.Fingerprint},
			Properties: sarif.PropertyBag{
				"severity":            string(f.Severity),
				"security-severity":   securitySeverity(f.Severity),
				"vulnetix/kind":       "iac",
				"vulnetix/subject":    f.Subject,
				"vulnetix/confidence": string(f.Confidence),
			},
		}
		if len(f.Adjustments) > 0 {
			res.Properties["vulnetix/adjustments"] = f.Adjustments
			// Facts moved the severity, so the rule's vector no longer
			// describes this result; carry the adjusted one.
			vec, _ := f.CWSS(rep.rule(f.RuleID))
			res.Properties["cwss"] = vec
		}
		if len(f.Evidence) > 0 {
			res.Properties["vulnetix/evidence"] = f.Evidence
		}
		if f.Fix != nil {
			res.Properties["vulnetix/fix"] = f.Fix
		}
		res.Locations = []sarif.Location{location(f)}
		results = append(results, res)
	}

	run := sarif.Run{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{
			Name: ToolName, FullName: "Vulnesis GitHub posture analysis", Organization: "Vulnesis",
			Version: opt.ToolVersion, InformationURI: "https://www.vulnes.is", Rules: rules,
		}},
		Results:           results,
		AutomationDetails: &sarif.RunAutomationDetails{ID: "vulnetix-github/"},
	}
	if opt.RepositoryURI != "" {
		run.VersionControlProvenance = []sarif.VersionControlDetails{{RepositoryURI: opt.RepositoryURI, Branch: opt.Branch, RevisionID: opt.Revision}}
	}
	var notes []string
	for _, cv := range rep.Coverage {
		if cv.State == "unknown" {
			notes = append(notes, cv.RuleID+" not evaluated: "+cv.Reason)
		}
	}
	notes = append(notes, rep.Errors...)
	l := &sarif.Log{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarif.Run{run}}
	l.AddExecutionNotifications(uniq(notes))
	return l
}

// location renders a finding's location. Settings findings point at a
// logical location (the settings page) rather than a file, using the
// repository root as the artifact so SARIF consumers that require a
// physical location still accept them.
func location(f *Finding) sarif.Location {
	if f.Location.Path == "" {
		return sarif.Location{
			PhysicalLocation: &sarif.PhysicalLocation{ArtifactLocation: &sarif.ArtifactLocation{URI: ".github"}},
			Message:          &sarif.Message{Text: "settings: " + f.Location.SettingsPath},
			Properties:       sarif.PropertyBag{"vulnetix/settingsPath": f.Location.SettingsPath, "vulnetix/scope": f.Location.Scope},
		}
	}
	reg := &sarif.Region{StartLine: max(f.Location.StartLine, 1), StartColumn: f.Location.StartCol}
	if f.Location.EndLine > reg.StartLine {
		reg.EndLine = f.Location.EndLine
	}
	if f.Location.Snippet != "" {
		reg.Snippet = &sarif.Snippet{Text: f.Location.Snippet}
	}
	return sarif.Location{PhysicalLocation: &sarif.PhysicalLocation{
		ArtifactLocation: &sarif.ArtifactLocation{URI: f.Location.Path},
		Region:           reg,
	}}
}

func precision(c Confidence) string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceLow:
		return "low"
	}
	return "medium"
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (rep *Report) rule(id string) *Rule {
	for _, r := range rep.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}
