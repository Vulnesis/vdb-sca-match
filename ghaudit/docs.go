package ghaudit

import (
	"fmt"
	"strings"
)

// CatalogueMarkdown renders the rule catalogue as Markdown, grouped by task.
// docs/ghaudit-rules.md is generated from it and checked by a test, and the
// CLI and website docs render the same text.
func CatalogueMarkdown() string {
	var b strings.Builder
	b.WriteString("# Vulnesis GitHub posture rules\n\n")
	b.WriteString("Generated from `ghaudit` — do not edit by hand; run `go test ./ghaudit -run TestCatalogueDoc -update`.\n\n")
	b.WriteString("Rules marked *needs* only run when those facts were collected (via the GitHub API or the GitHub App); without them they are reported as not evaluated rather than passed. Rules marked *uses* run on files alone and use the facts, when present, to lower severity where a setting removes the risk and raise it where a setting makes it worse.\n")
	titles := map[Task]string{
		TaskWorkflows: "Workflows — `vulnesis gha workflows`",
		TaskActions:   "Actions and images — `vulnesis gha actions`",
		TaskSettings:  "Repository settings — `vulnesis gha settings`",
		TaskOrg:       "Organisation settings — `vulnesis gha org`",
	}
	for _, t := range AllTasks {
		fmt.Fprintf(&b, "\n## %s\n\n| ID | Rule | Severity | CWE | Context |\n|---|---|---|---|---|\n", titles[t])
		for _, r := range Rules() {
			if r.Task != t {
				continue
			}
			cwes := make([]string, len(r.CWE))
			for i, c := range r.CWE {
				cwes[i] = fmt.Sprintf("CWE-%d", c)
			}
			ctx := []string{}
			if len(r.Requires) > 0 {
				ctx = append(ctx, "needs "+strings.Join(r.Requires, ", "))
			}
			if len(r.Enhances) > 0 {
				ctx = append(ctx, "uses "+strings.Join(r.Enhances, ", "))
			}
			fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s | %s |\n", r.ID, strings.ToLower(r.ID), r.Name, r.Severity, strings.Join(cwes, ", "), strings.Join(ctx, "; "))
		}
	}
	b.WriteString("\n## Rule details\n")
	for _, r := range Rules() {
		fmt.Fprintf(&b, "\n### %s\n\n**%s** — %s\n\n%s\n\n**Remediation.** %s\n", r.ID, r.Name, r.Summary, r.Description, r.Remediation)
	}
	return b.String()
}
