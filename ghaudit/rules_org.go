package ghaudit

import (
	"fmt"
	"strings"
)

func orgFinding(subj, settingsPath, msg string) *Finding {
	return &Finding{Subject: "org#" + subj, Location: Location{SettingsPath: settingsPath, Scope: "org"}, Message: msg}
}

func (c *Context) org() *OrgFacts {
	if c.Facts == nil {
		return nil
	}
	return c.Facts.Org
}

var _ = register(&Rule{
	ID: "VNX-GH-301", Name: "Organisation does not require two-factor authentication", Task: TaskOrg,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{308},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"scm", "identity"},
	Summary:     "Members and outside collaborators can sign in with a password alone.",
	Description: "Every member account is a path to every repository it can write to. Phished or reused passwords are the most common way into an organisation.",
	Remediation: "Require two-factor authentication for the organisation.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || o.TwoFactorRequired == nil || *o.TwoFactorRequired {
			return nil
		}
		return []*Finding{orgFinding("2fa", "settings/security", fmt.Sprintf("Organisation %s does not require two-factor authentication.", o.Login))}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-302", Name: "Broad default repository permission for members", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{276},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "access", "least-privilege"},
	Summary:     "Every member gets write or admin on every repository.",
	Description: "With a write default, one compromised member account can push to, and run workflows in, every repository in the organisation.",
	Remediation: "Set the base permission to read or none and grant write through teams.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || (o.DefaultRepositoryPermission != "write" && o.DefaultRepositoryPermission != "admin") {
			return nil
		}
		fd := orgFinding("base-permission", "settings/member_privileges", fmt.Sprintf("Members have %s on every repository by default.", o.DefaultRepositoryPermission))
		if o.DefaultRepositoryPermission == "admin" {
			fd.Severity = High
		}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-303", Name: "Members can create public repositories", Task: TaskOrg,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{200},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"scm", "data-exposure"},
	Summary:     "Any member can publish a repository under the organisation's name.",
	Description: "Public repositories can be created by mistake with internal code, or used to host look-alike actions that appear to be official.",
	Remediation: "Restrict public repository creation to owners.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || !boolp(o.MembersCanCreatePublicRepos) {
			return nil
		}
		return []*Finding{orgFinding("public-repos", "settings/member_privileges", "Members can create public repositories.")}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-304", Name: "Organisation allows any action", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{829},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "policy"},
	Summary:     "The organisation policy permits every action and reusable workflow in every repository.",
	Description: "An organisation-wide allow-list is the one control that stops a new, unreviewed third-party action from running anywhere.",
	Remediation: "Allow GitHub-owned, verified-creator and explicitly listed actions only.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || o.AllowedActions != "all" {
			return nil
		}
		return []*Finding{orgFinding("actions/allowed", "settings/actions", "All actions are allowed across the organisation.")}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-305", Name: "Organisation workflow token defaults to write", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{250, 276},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "least-privilege"},
	Summary:     "New repositories inherit a read/write workflow token.",
	Description: "The organisation default sets the ceiling for every repository that does not override it, including every repository created from now on.",
	Remediation: "Set the organisation's default workflow permissions to read.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || o.DefaultWorkflowPermissions != "write" {
			return nil
		}
		fd := orgFinding("actions/default-permissions", "settings/actions", "The organisation's default GITHUB_TOKEN permission is read/write.")
		fd.Fix = &Fix{Description: "Set the organisation default to read.", Setting: "org.actions.default_workflow_permissions=read"}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-306", Name: "Organisation secret visible to every repository", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{200, 668},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "An organisation secret has visibility all, so any repository — including public ones — can read it.",
	Description: "A secret shared with all repositories is only as safe as the weakest workflow in the organisation. With visibility all, public repositories' workflows can read it too.",
	Remediation: "Set the secret's visibility to selected repositories, or private repositories at most.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil {
			return nil
		}
		var out []*Finding
		for _, s := range o.Secrets {
			if s.Visibility != "all" {
				continue
			}
			out = append(out, orgFinding("secret:"+strings.ToLower(s.Name), "settings/secrets/actions", fmt.Sprintf("Organisation secret %s is visible to all repositories, including public ones.", s.Name)))
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-307", Name: "Self-hosted runners available to public repositories", Task: TaskOrg,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{668, 829},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "runners"},
	Summary:     "A runner group with self-hosted runners allows public repositories.",
	Description: "Any GitHub user can trigger pull_request workflows in a public repository. If those jobs can land on your self-hosted runners, outsiders run code inside your network.",
	Remediation: "Disable \"Allow public repositories\" on runner groups that contain self-hosted runners, or make those runners ephemeral and network-isolated.",
	Requires:    []string{FactRunnerGroups},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, g := range c.Facts.RunnerGroups {
			if !g.AllowsPublicRepositories || g.SelfHostedRunners == 0 {
				continue
			}
			out = append(out, orgFinding("runner-group:"+strings.ToLower(g.Name), "settings/actions/runner-groups", fmt.Sprintf("Runner group %q has %d self-hosted runner(s) and allows public repositories.", g.Name, g.SelfHostedRunners)))
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-308", Name: "Organisation lets Actions approve pull requests", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "code-review"},
	Summary:     "Workflows across the organisation may create and approve pull requests.",
	Description: "Repositories inherit this permission; a workflow token can then satisfy one-approval rules by approving its own pull request.",
	Remediation: "Disable \"Allow GitHub Actions to create and approve pull requests\" at the organisation level.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil || !boolp(o.CanApprovePullRequestReviews) {
			return nil
		}
		return []*Finding{orgFinding("actions/approve-prs", "settings/actions", "GitHub Actions may create and approve pull requests across the organisation.")}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-309", Name: "Organisation webhook deliveries can be forged or intercepted", Task: TaskOrg,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{345, 295},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "webhooks"},
	Summary:     "An organisation webhook has no secret, or disables TLS verification.",
	Description: "Organisation webhooks receive events from every repository. An unsigned or unverified hook lets an attacker forge or read them.",
	Remediation: "Set a webhook secret and enable SSL verification.",
	Requires:    []string{FactOrg},
	check: func(c *Context) []*Finding {
		o := c.org()
		if o == nil {
			return nil
		}
		return webhookFindings(o.Webhooks, "org#", "settings/hooks", "org")
	},
})
