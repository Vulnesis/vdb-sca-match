package ghaudit

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// settingsFinding builds a repository-scope finding.
func settingsFinding(subj, settingsPath, msg string) *Finding {
	return &Finding{Subject: "repo#" + subj, Location: Location{SettingsPath: settingsPath, Scope: "repo"}, Message: msg}
}

// defaultBranch returns the default branch's protection facts.
func (c *Context) defaultBranch() (string, *BranchFacts) {
	r := c.Repo()
	if r == nil || r.DefaultBranch == "" || c.Facts.Branches == nil {
		return "", nil
	}
	return r.DefaultBranch, c.Facts.Branches[r.DefaultBranch]
}

// protectionCheck is a default-branch protection rule body.
func protectionCheck(fn func(c *Context, name string, b *BranchFacts) *Finding) func(*Context) []*Finding {
	return func(c *Context) []*Finding {
		if r := c.Repo(); r == nil || r.Archived {
			return nil
		}
		name, b := c.defaultBranch()
		if name == "" || b == nil || !b.Protected {
			return nil // unprotected is reported once, by VNX-GH-201
		}
		if fd := fn(c, name, b); fd != nil {
			return []*Finding{fd}
		}
		return nil
	}
}

// publicBoost raises severity for public repositories, where any GitHub user
// can open the pull request the control is meant to stop.
func (c *Context) publicBoost(fd *Finding) {
	if c.Repo().Public() {
		fd.adjust(1, "repository is public")
	}
}

var _ = register(&Rule{
	ID: "VNX-GH-201", Name: "Default branch is not protected", Task: TaskSettings,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{284, 862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection"},
	Summary:     "Neither branch protection nor a ruleset applies to the default branch.",
	Description: "Anyone with write access — including a compromised token, a leaked deploy key, or a workflow with contents: write — can push directly to the default branch, rewrite its history or delete it, and the change ships without review.",
	Remediation: "Add a ruleset targeting the default branch that requires pull requests with at least one approval, blocks force pushes and deletions, and requires status checks.",
	Requires:    []string{FactRepo, FactBranches},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if r == nil || r.Archived {
			return nil
		}
		name, b := c.defaultBranch()
		if name == "" || (b != nil && b.Protected) {
			return nil
		}
		fd := settingsFinding("branch:"+name+"/protection", "settings/rules", fmt.Sprintf("Default branch %q has no branch protection or ruleset.", name))
		fd.Fix = &Fix{Description: "Create a default-branch ruleset.", Setting: "rulesets.default_branch=pull_request,non_fast_forward,deletion"}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-202", Name: "Default branch merges without review", Task: TaskSettings,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection", "code-review"},
	Summary:     "Protection exists but requires no approving review.",
	Description: "Without a required approval a single account — or a single stolen credential — can land any change on the default branch.",
	Remediation: "Require at least one approving review (two for repositories that publish releases), and require approval of the most recent push.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		if b.RequiredApprovals > 0 {
			return nil
		}
		return settingsFinding("branch:"+name+"/reviews", "settings/rules", fmt.Sprintf("Default branch %q requires no approving reviews.", name))
	}),
})

var _ = register(&Rule{
	ID: "VNX-GH-203", Name: "Approvals survive new commits", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection", "code-review"},
	Summary:     "Stale reviews are not dismissed and approval of the last push is not required.",
	Description: "An author can get a harmless change approved, then push different code and merge on the old approval.",
	Remediation: "Enable dismiss stale approvals and require approval of the most recent reviewable push.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		if b.RequiredApprovals == 0 || b.DismissStaleReviews || b.RequireLastPushApproval {
			return nil
		}
		return settingsFinding("branch:"+name+"/stale-reviews", "settings/rules", fmt.Sprintf("Default branch %q keeps approvals after new commits are pushed.", name))
	}),
})

// coversWorkflows reports whether some CODEOWNERS rule matches .github/workflows.
func coversWorkflows(rules []CodeOwnersRule) bool {
	for _, r := range rules {
		p := strings.TrimPrefix(r.Pattern, "/")
		if len(r.Owners) == 0 {
			continue
		}
		if p == "*" || p == "**" || strings.HasPrefix(".github/workflows/", strings.TrimSuffix(strings.TrimSuffix(p, "*"), "/")+"/") || p == ".github/" || p == ".github" || p == ".github/**" || p == ".github/workflows" {
			return true
		}
		if ok, _ := path.Match(p, ".github/workflows/ci.yml"); ok {
			return true
		}
	}
	return false
}

var _ = register(&Rule{
	ID: "VNX-GH-204", Name: "Workflow changes bypass code owners", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "codeowners", "ci-cd"},
	Summary:     "CODEOWNERS does not cover .github/workflows, or code owner review is not required.",
	Description: "Workflows hold the keys: secrets, deployment credentials and release signing. If any approver can sign off a workflow change, a reviewer unfamiliar with CI security can approve a change that exfiltrates secrets.",
	Remediation: "Add `/.github/ @your-org/ci-owners` to CODEOWNERS and require code owner review on the default branch.",
	Requires:    []string{FactRepo, FactBranches, FactCodeOwners},
	check: func(c *Context) []*Finding {
		name, b := c.defaultBranch()
		if name == "" || b == nil || !b.Protected || len(c.Workflows()) == 0 {
			return nil
		}
		has := c.Facts.HasCodeOwners != nil && *c.Facts.HasCodeOwners
		switch {
		case !has || !coversWorkflows(c.Facts.CodeOwners):
			return []*Finding{settingsFinding("codeowners/workflows", "blob/"+name+"/.github/CODEOWNERS", "No CODEOWNERS rule covers .github/workflows.")}
		case !b.RequireCodeOwnerReviews:
			return []*Finding{settingsFinding("branch:"+name+"/codeowner-review", "settings/rules", fmt.Sprintf("CODEOWNERS covers workflows, but default branch %q does not require code owner review.", name))}
		}
		return nil
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-205", Name: "Force pushes or deletion allowed on the default branch", Task: TaskSettings,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{284},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection"},
	Summary:     "Protection permits force pushes or deleting the branch.",
	Description: "A force push rewrites history that downstream builds, tags and audits rely on, and can remove a reviewed change after the fact.",
	Remediation: "Block force pushes and deletions on the default branch.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		if !b.AllowForcePushes && !b.AllowDeletions {
			return nil
		}
		var what []string
		if b.AllowForcePushes {
			what = append(what, "force pushes")
		}
		if b.AllowDeletions {
			what = append(what, "deletion")
		}
		return settingsFinding("branch:"+name+"/history", "settings/rules", fmt.Sprintf("Default branch %q allows %s.", name, strings.Join(what, " and ")))
	}),
})

var _ = register(&Rule{
	ID: "VNX-GH-206", Name: "Branch protection can be bypassed", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{284, 863},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection"},
	Summary:     "Administrators are exempt, or a broad role or app is a ruleset bypass actor.",
	Description: "An exemption is a standing path around review. Admin accounts and app installations are the highest-value credentials to steal precisely because they skip the controls.",
	Remediation: "Enforce protection for administrators and limit ruleset bypass to a named break-glass team with pull-request-only bypass.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		var broad []string
		for _, a := range b.BypassActors {
			la := strings.ToLower(a)
			if strings.HasPrefix(la, "repositoryrole:write") || strings.HasPrefix(la, "repositoryrole:maintain") || strings.HasPrefix(la, "integration:") || la == "organizationadmin" {
				broad = append(broad, a)
			}
		}
		if b.EnforceAdmins && len(broad) == 0 {
			return nil
		}
		msg := fmt.Sprintf("Default branch %q protection can be bypassed", name)
		if !b.EnforceAdmins {
			msg += " by administrators"
		}
		if len(broad) > 0 {
			msg += " by " + strings.Join(broad, ", ")
		}
		fd := settingsFinding("branch:"+name+"/bypass", "settings/rules", msg+".")
		fd.Evidence = map[string]any{"bypassActors": b.BypassActors, "enforceAdmins": b.EnforceAdmins}
		return fd
	}),
})

var _ = register(&Rule{
	ID: "VNX-GH-207", Name: "No required status checks", Task: TaskSettings,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{754},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection"},
	Summary:     "Pull requests can merge with failing or missing CI.",
	Description: "Security checks (tests, scanners, signature verification) only protect the branch if a failing result blocks the merge.",
	Remediation: "Require the security-relevant checks to pass before merging.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		if len(b.RequiredStatusChecks) > 0 || len(c.Workflows()) == 0 {
			return nil
		}
		return settingsFinding("branch:"+name+"/status-checks", "settings/rules", fmt.Sprintf("Default branch %q requires no status checks, although the repository has %d workflows.", name, len(c.Workflows())))
	}),
})

var _ = register(&Rule{
	ID: "VNX-GH-208", Name: "Workflow token defaults to write", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{250, 276},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "least-privilege"},
	Summary:     "Workflows without a permissions: block get a read/write token.",
	Description: "Every workflow that omits permissions: — including ones added later by contributors — runs with write access to contents, packages, issues and pull requests.",
	Remediation: "Set Settings → Actions → General → Workflow permissions to \"Read repository contents and packages permissions\".",
	Requires:    []string{FactRepo, FactActionsPolicy},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if r.DefaultWorkflowPermissions != "write" {
			return nil
		}
		fd := settingsFinding("actions/default-permissions", "settings/actions", "The default GITHUB_TOKEN permission is read/write.")
		var undeclared int
		for _, f := range c.Workflows() {
			for _, j := range f.Jobs {
				if f.Permissions == nil && j.Permissions == nil && j.Uses == nil {
					undeclared++
				}
			}
		}
		if undeclared > 0 {
			fd.Message += fmt.Sprintf(" %d job(s) in this repository rely on it.", undeclared)
			fd.adjust(1, "jobs in this repository inherit the default")
		}
		fd.Fix = &Fix{Description: "Set the default workflow permission to read.", Setting: "actions.default_workflow_permissions=read"}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-209", Name: "GitHub Actions can approve pull requests", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "code-review"},
	Summary:     "Workflows may create and approve pull requests.",
	Description: "A workflow token that can approve pull requests satisfies a one-approval rule on its own: one compromised workflow opens and approves its own change.",
	Remediation: "Disable \"Allow GitHub Actions to create and approve pull requests\".",
	Requires:    []string{FactRepo, FactActionsPolicy},
	check: func(c *Context) []*Finding {
		if !boolp(c.Repo().CanApprovePullRequestReviews) {
			return nil
		}
		fd := settingsFinding("actions/approve-prs", "settings/actions", "GitHub Actions is allowed to create and approve pull requests.")
		if _, b := c.defaultBranch(); b != nil && b.RequiredApprovals == 1 {
			fd.adjust(1, "default branch needs exactly one approval, which a workflow can supply")
		}
		fd.Fix = &Fix{Description: "Disallow Actions from approving pull requests.", Setting: "actions.can_approve_pull_request_reviews=false"}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-210", Name: "Fork pull request workflows run without approval", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{862},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "forks"},
	Summary:     "Outside contributors' pull requests run workflows without a maintainer approving them, or private-repo forks get secrets or write tokens.",
	Description: "Approval is the human check before an outsider's code runs on your runners. Only requiring it for accounts new to GitHub lets any established account — or a bought one — run code immediately. On private repositories, sending secrets or write tokens to fork workflows hands them to every fork.",
	Remediation: "Require approval for all outside collaborators; on private repositories, do not send write tokens or secrets to fork pull request workflows.",
	Requires:    []string{FactRepo, FactActionsPolicy},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		var out []*Finding
		if r.Public() && r.ForkPRApproval != "" && r.ForkPRApproval != "all_external_contributors" {
			fd := settingsFinding("actions/fork-approval", "settings/actions", fmt.Sprintf("Fork pull request workflows need approval only for %s.", strings.ReplaceAll(r.ForkPRApproval, "_", " ")))
			for _, f := range c.Workflows() {
				if f.HasTrigger("pull_request") {
					for _, j := range f.Jobs {
						if selfHosted(j.RunsOn) {
							fd.adjust(1, "a pull_request workflow runs on self-hosted runners")
							break
						}
					}
				}
			}
			out = append(out, fd)
		}
		if !r.Public() && boolp(r.ForkPRWorkflowsEnabled) {
			if boolp(r.ForkPRSendSecrets) || boolp(r.ForkPRSendWriteTokens) {
				fd := settingsFinding("actions/fork-secrets", "settings/actions", "Fork pull request workflows receive secrets or a write token.")
				fd.Severity = High
				out = append(out, fd)
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-211", Name: "Any action may run", Task: TaskSettings,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{829},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "policy"},
	Summary:     "The allowed-actions policy permits every action and reusable workflow.",
	Description: "With no allow-list a contributor can introduce any third-party action in a pull request, and it runs on merge with the workflow's token and secrets.",
	Remediation: "Allow GitHub-owned and verified-creator actions plus an explicit list, and require SHA pinning.",
	Requires:    []string{FactRepo, FactActionsPolicy},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if r.AllowedActions != "all" {
			return nil
		}
		fd := settingsFinding("actions/allowed", "settings/actions", "All actions and reusable workflows are allowed.")
		if !boolp(r.SHAPinningRequired) {
			fd.Message += " SHA pinning is not required either."
			fd.adjust(1, "SHA pinning is not required")
		}
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-212", Name: "Secret scanning or push protection disabled", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{798},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "secrets"},
	Summary:     "Committed credentials are neither blocked at push time nor alerted on.",
	Description: "Push protection stops a credential before it reaches history; secret scanning finds the ones that got through. Without either, a leaked key is found first by whoever is looking.",
	Remediation: "Enable secret scanning and push protection.",
	Requires:    []string{FactRepo, FactSecurity},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		var off []string
		if r.SecretScanning != nil && !*r.SecretScanning {
			off = append(off, "secret scanning")
		}
		if r.PushProtection != nil && !*r.PushProtection {
			off = append(off, "push protection")
		}
		if len(off) == 0 {
			return nil
		}
		fd := settingsFinding("security/secret-scanning", "settings/security_analysis", strings.Join(off, " and ")+" disabled.")
		fd.Message = strings.ToUpper(fd.Message[:1]) + fd.Message[1:]
		c.publicBoost(fd)
		return []*Finding{fd}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-213", Name: "Dependabot security updates disabled", Task: TaskSettings,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{1104},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"scm", "dependencies"},
	Summary:     "Vulnerable dependencies, including pinned actions, are not raised as update pull requests.",
	Description: "SHA-pinned actions only stay safe if something updates them. Security updates open the fix as a pull request as soon as an advisory is published.",
	Remediation: "Enable Dependabot security updates, and add a github-actions ecosystem entry to dependabot.yml.",
	Requires:    []string{FactRepo, FactSecurity},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if r.DependabotUpdates == nil || *r.DependabotUpdates {
			return nil
		}
		return []*Finding{settingsFinding("security/dependabot", "settings/security_analysis", "Dependabot security updates are disabled.")}
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-214", Name: "Environment secrets deployable without approval", Task: TaskSettings,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{284, 862},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "environments", "secrets"},
	Summary:     "An environment holds secrets but has no required reviewers and no branch policy.",
	Description: "Environment secrets exist so that only gated jobs see them. An ungated environment gives its secrets to any job on any branch that names it — including a branch pushed by any writer.",
	Remediation: "Add required reviewers (with prevent self-review) or restrict the environment to protected branches.",
	Requires:    []string{FactRepo, FactEnvironments},
	check: func(c *Context) []*Finding {
		var out []*Finding
		names := make([]string, 0, len(c.Facts.Envs))
		for n := range c.Facts.Envs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			e := c.Facts.Envs[n]
			if len(e.SecretNames) == 0 || e.Protected() {
				continue
			}
			fd := settingsFinding("environment:"+n, "settings/environments", fmt.Sprintf("Environment %q has %d secret(s) and no reviewers or branch policy.", n, len(e.SecretNames)))
			fd.Evidence = map[string]any{"secrets": e.SecretNames}
			for _, f := range c.Workflows() {
				if trig, ok := privileged(f); ok {
					for _, j := range f.Jobs {
						if j.Environment == n {
							fd.adjust(1, fmt.Sprintf("%s uses it from a %s workflow", f.Path, trig))
						}
					}
				}
			}
			out = append(out, fd)
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-215", Name: "Deploy key with write access", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{732},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "credentials"},
	Summary:     "A deploy key can push to the repository.",
	Description: "Deploy keys are not tied to a user, do not expire, and are typically stored on build or deployment hosts. A write key there can push to unprotected branches and tags.",
	Remediation: "Make the key read-only, or replace it with a GitHub App installation token scoped to the repository.",
	Requires:    []string{FactDeployKeys},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, k := range c.Facts.DeployKeys {
			if k.ReadOnly {
				continue
			}
			fd := settingsFinding(fmt.Sprintf("deploy-key:%d", k.ID), "settings/keys", fmt.Sprintf("Deploy key %q has write access.", k.Title))
			if k.AgeDays > 365 {
				fd.adjust(1, fmt.Sprintf("key is %d days old", k.AgeDays))
			}
			out = append(out, fd)
		}
		return out
	},
})

func webhookFindings(hooks []WebhookFacts, prefix, settings string, scope string) []*Finding {
	var out []*Finding
	for _, h := range hooks {
		if !h.Active {
			continue
		}
		var why []string
		if !h.HasSecret {
			why = append(why, "has no secret, so receivers cannot verify deliveries")
		}
		if h.InsecureSSL {
			why = append(why, "skips TLS certificate verification")
		}
		if len(why) == 0 {
			continue
		}
		fd := &Finding{Subject: prefix + fmt.Sprintf("webhook:%d", h.ID), Location: Location{SettingsPath: settings, Scope: scope}, Message: fmt.Sprintf("Webhook to %s %s.", h.URL, strings.Join(why, " and "))}
		if h.InsecureSSL {
			fd.Severity = High
		}
		out = append(out, fd)
	}
	return out
}

var _ = register(&Rule{
	ID: "VNX-GH-216", Name: "Webhook deliveries can be forged or intercepted", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{345, 295},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "webhooks"},
	Summary:     "A repository webhook has no secret, or disables TLS verification.",
	Description: "Webhooks often drive deployments. Without a signing secret anyone can forge an event; without TLS verification the payload (and anything it triggers) can be intercepted or altered.",
	Remediation: "Set a webhook secret and verify X-Hub-Signature-256 on receipt; enable SSL verification.",
	Requires:    []string{FactWebhooks},
	check: func(c *Context) []*Finding {
		return webhookFindings(c.Facts.Webhooks, "repo#", "settings/hooks", "repo")
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-217", Name: "Outside collaborator with admin access", Task: TaskSettings,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{269},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"scm", "access"},
	Summary:     "Someone outside the organisation can change protection, secrets and settings.",
	Description: "Admin access includes disabling branch protection, reading environment configuration and adding deploy keys. Outside collaborators are not covered by the organisation's 2FA, SSO and offboarding.",
	Remediation: "Reduce outside collaborators to write or lower, or bring them into the organisation.",
	Requires:    []string{FactCollaborators},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, col := range c.Facts.Collaborators {
			if !col.Outside || (col.Permission != "admin" && col.Permission != "maintain") {
				continue
			}
			fd := settingsFinding("collaborator:"+strings.ToLower(col.Login), "settings/access", fmt.Sprintf("Outside collaborator %s has %s access.", col.Login, col.Permission))
			if col.Permission == "maintain" {
				fd.adjust(-1, "maintain cannot change protection or secrets")
			}
			out = append(out, fd)
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-218", Name: "Signed commits not required", Task: TaskSettings,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{345},
	CWSS:        "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"scm", "branch-protection", "provenance"},
	Summary:     "The default branch accepts unsigned commits.",
	Description: "Commit author fields are free text. Without signature verification a commit can claim any author, which undermines audit trails and author-based automation.",
	Remediation: "Require signed commits on the default branch.",
	Requires:    []string{FactRepo, FactBranches},
	check: protectionCheck(func(c *Context, name string, b *BranchFacts) *Finding {
		if b.RequireSignedCommits {
			return nil
		}
		return settingsFinding("branch:"+name+"/signatures", "settings/rules", fmt.Sprintf("Default branch %q does not require signed commits.", name))
	}),
})

var _ = register(&Rule{
	ID: "VNX-GH-219", Name: "Repository secret used by an untrusted-trigger workflow", Task: TaskSettings,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{200, 668},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "A repository-level secret (not an environment secret) is read by a workflow outsiders can trigger.",
	Description: "Repository secrets are available to every job. When a pull_request_target, issue_comment or workflow_run workflow reads one, any flaw in that workflow exposes it; an environment secret would add a gate.",
	Remediation: "Move the secret to an environment with required reviewers, and reference it only from the job bound to that environment.",
	Requires:    []string{FactRepo},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if len(r.SecretNames) == 0 {
			return nil
		}
		repoSecrets := map[string]bool{}
		for _, s := range r.SecretNames {
			repoSecrets[strings.ToUpper(s)] = true
		}
		var out []*Finding
		for _, f := range c.Workflows() {
			trig, ok := privileged(f)
			if !ok {
				continue
			}
			for i, line := range f.Lines {
				for _, e := range Expressions(line) {
					for _, ref := range ContextRefs(e.Body) {
						name := strings.ToUpper(strings.TrimPrefix(ref, "secrets."))
						if !strings.HasPrefix(ref, "secrets.") || !repoSecrets[name] {
							continue
						}
						out = append(out, &Finding{
							Subject:  "repo#secret:" + strings.ToLower(name) + "@" + f.Path,
							Location: Location{Path: f.Path, StartLine: i + 1, EndLine: i + 1, Snippet: strings.TrimSpace(line)},
							Message:  fmt.Sprintf("Repository secret %s is read by %s, which runs on %s.", name, f.Path, trig),
						})
					}
				}
			}
		}
		return out
	},
})
