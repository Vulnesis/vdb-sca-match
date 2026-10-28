package ghaudit

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Getter performs one authenticated GitHub REST GET. path is API-relative
// ("/repos/o/r"), already escaped. out is decoded from the JSON body when
// non-nil. It returns the HTTP status; err is non-nil for transport errors
// and for any status outside 2xx (the status is still returned).
type Getter interface {
	Get(ctx context.Context, path string, out any) (int, error)
}

// CollectOptions bounds a collection.
type CollectOptions struct {
	Repo string // owner/name; empty for an organisation-only collection
	Org  string // organisation login; empty to skip organisation facts
	// Ref is the branch, tag or SHA whose files are read; empty means the
	// default branch.
	Ref string
	// Files are already in hand (a webhook payload's head, a local checkout):
	// skip reading repository files.
	SkipFiles bool
	// MaxFiles caps workflow/action files read (default 60).
	MaxFiles int
	// MaxActionRefs caps distinct uses: references resolved (default 40;
	// negative disables resolution).
	MaxActionRefs int
	// Advisories, when set, looks up published advisories for an action at
	// a ref (the platform answers from its vulnerability database).
	Advisories func(ctx context.Context, action, ref, sha string) []ActionAdvisory
	Now        time.Time
}

// Collected is what Collect read.
type Collected struct {
	Files   map[string][]byte
	Facts   *Facts
	HeadSHA string
	Ref     string
	// Notes says what could not be read and why, for the run's report.
	Notes []string
}

type collector struct {
	ctx   context.Context
	g     Getter
	opt   CollectOptions
	out   *Collected
	facts *Facts
}

func (c *collector) get(p string, out any) (int, error) {
	st, err := c.g.Get(c.ctx, p, out)
	if err != nil && st == 0 {
		return 0, err
	}
	return st, err
}

func (c *collector) note(format string, a ...any) {
	c.out.Notes = append(c.out.Notes, fmt.Sprintf(format, a...))
}

func (c *collector) mark(group string) { c.facts.Collected[group] = true }

func esc(s string) string { return url.PathEscape(s) }

func repoPath(repo string) string {
	o, r, _ := strings.Cut(repo, "/")
	return "/repos/" + esc(o) + "/" + esc(r)
}

// Collect reads files and facts for one repository and/or organisation.
// It never fails a whole collection for one unreadable fact: the fact group
// is left uncollected (its rules report "unknown") and a note says why.
func Collect(ctx context.Context, g Getter, opt CollectOptions) (*Collected, error) {
	if opt.MaxFiles == 0 {
		opt.MaxFiles = 60
	}
	if opt.MaxActionRefs == 0 {
		opt.MaxActionRefs = 40
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	c := &collector{ctx: ctx, g: g, opt: opt, out: &Collected{Files: map[string][]byte{}}, facts: &Facts{Collected: map[string]bool{}}}
	c.out.Facts = c.facts
	if opt.Repo != "" {
		if err := c.repo(); err != nil {
			return c.out, err
		}
	}
	if opt.Org != "" {
		c.org()
	}
	if opt.Repo != "" && opt.MaxActionRefs > 0 {
		c.actionRefs()
	}
	return c.out, nil
}

func (c *collector) repo() error {
	rp := repoPath(c.opt.Repo)
	var info struct {
		FullName      string `json:"full_name"`
		Private       bool   `json:"private"`
		Visibility    string `json:"visibility"`
		DefaultBranch string `json:"default_branch"`
		Archived      bool   `json:"archived"`
		Fork          bool   `json:"fork"`
		AllowForking  *bool  `json:"allow_forking"`
		Security      *struct {
			SecretScanning *struct {
				Status string `json:"status"`
			} `json:"secret_scanning"`
			PushProtection *struct {
				Status string `json:"status"`
			} `json:"secret_scanning_push_protection"`
			DependabotUpdates *struct {
				Status string `json:"status"`
			} `json:"dependabot_security_updates"`
		} `json:"security_and_analysis"`
	}
	if st, err := c.get(rp, &info); err != nil {
		return fmt.Errorf("read %s: HTTP %d: %w", c.opt.Repo, st, err)
	}
	vis := info.Visibility
	if vis == "" {
		vis = map[bool]string{true: "private", false: "public"}[info.Private]
	}
	r := &RepoFacts{FullName: info.FullName, Visibility: vis, DefaultBranch: info.DefaultBranch, Archived: info.Archived, Fork: info.Fork, AllowForking: info.AllowForking}
	c.facts.Repo = r
	c.mark(FactRepo)

	if s := info.Security; s != nil {
		on := func(x *struct {
			Status string `json:"status"`
		}) *bool {
			if x == nil {
				return nil
			}
			v := x.Status == "enabled"
			return &v
		}
		r.SecretScanning, r.PushProtection, r.DependabotUpdates = on(s.SecretScanning), on(s.PushProtection), on(s.DependabotUpdates)
		c.mark(FactSecurity)
	} else {
		c.note("security_and_analysis not visible (needs admin access)")
	}
	switch st, _ := c.get(rp+"/vulnerability-alerts", nil); st {
	case 204, 200:
		r.DependabotAlerts = boolPtr(true)
	case 404:
		r.DependabotAlerts = boolPtr(false)
	}
	if r.Public() {
		var pvr struct {
			Enabled bool `json:"enabled"`
		}
		if st, _ := c.get(rp+"/private-vulnerability-reporting", &pvr); st == 200 {
			r.PrivateVulnReporting = &pvr.Enabled
		}
	}

	c.actionsPolicy(rp, r)
	ref := c.opt.Ref
	if ref == "" {
		ref = r.DefaultBranch
	}
	c.out.Ref = ref
	c.branch(rp, r.DefaultBranch)
	c.environments(rp)
	c.secrets(rp, r)
	c.keysHooksCollaborators(rp)
	c.files(rp, ref)
	return nil
}

func boolPtr(b bool) *bool { return &b }

func (c *collector) actionsPolicy(rp string, r *RepoFacts) {
	var ap struct {
		Enabled            bool   `json:"enabled"`
		AllowedActions     string `json:"allowed_actions"`
		SHAPinningRequired *bool  `json:"sha_pinning_required"`
	}
	st1, _ := c.get(rp+"/actions/permissions", &ap)
	var wp struct {
		Default    string `json:"default_workflow_permissions"`
		CanApprove bool   `json:"can_approve_pull_request_reviews"`
	}
	st2, _ := c.get(rp+"/actions/permissions/workflow", &wp)
	if st1 != 200 || st2 != 200 {
		c.note("Actions settings not readable (HTTP %d/%d; needs Administration: read)", st1, st2)
		return
	}
	r.ActionsEnabled = &ap.Enabled
	r.AllowedActions = ap.AllowedActions
	if r.AllowedActions == "" {
		r.AllowedActions = "all"
	}
	r.SHAPinningRequired = ap.SHAPinningRequired
	r.DefaultWorkflowPermissions = wp.Default
	r.CanApprovePullRequestReviews = &wp.CanApprove
	if r.AllowedActions == "selected" {
		var sel struct {
			GithubOwned bool     `json:"github_owned_allowed"`
			Verified    bool     `json:"verified_allowed"`
			Patterns    []string `json:"patterns_allowed"`
		}
		if st, _ := c.get(rp+"/actions/permissions/selected-actions", &sel); st != 200 {
			c.note("selected-actions list not readable")
			return
		}
		r.GithubOwnedAllowed, r.VerifiedAllowed, r.AllowedActionPatterns = &sel.GithubOwned, &sel.Verified, sel.Patterns
	}
	if r.Public() {
		var fa struct {
			Policy string `json:"approval_policy"`
		}
		if st, _ := c.get(rp+"/actions/permissions/fork-pr-contributor-approval", &fa); st == 200 {
			r.ForkPRApproval = fa.Policy
		}
	} else {
		var pf struct {
			Run      bool `json:"run_workflows_from_fork_pull_requests"`
			Write    bool `json:"send_write_tokens_to_workflows"`
			Secrets  bool `json:"send_secrets_and_variables"`
			Approval bool `json:"require_approval_for_fork_pr_workflows"`
		}
		if st, _ := c.get(rp+"/actions/permissions/fork-pr-workflows-private-repos", &pf); st == 200 {
			r.ForkPRWorkflowsEnabled, r.ForkPRSendWriteTokens, r.ForkPRSendSecrets, r.ForkPRRequireApproval = &pf.Run, &pf.Write, &pf.Secrets, &pf.Approval
		}
	}
	c.mark(FactActionsPolicy)
}

// repositoryRoles names the built-in repository role ids rulesets use for
// bypass actors.
var repositoryRoles = map[int64]string{1: "read", 2: "maintain", 3: "triage", 4: "write", 5: "admin"}

func (c *collector) branch(rp, name string) {
	if name == "" {
		return
	}
	b := &BranchFacts{Name: name, EnforceAdmins: true}
	var rules []struct {
		Type       string `json:"type"`
		RulesetID  int64  `json:"ruleset_id"`
		Parameters struct {
			Reviews        int  `json:"required_approving_review_count"`
			DismissStale   bool `json:"dismiss_stale_reviews_on_push"`
			CodeOwner      bool `json:"require_code_owner_review"`
			LastPush       bool `json:"require_last_push_approval"`
			RequiredChecks []struct {
				Context string `json:"context"`
			} `json:"required_status_checks"`
		} `json:"parameters"`
	}
	rulesOK := false
	if st, _ := c.get(rp+"/rules/branches/"+esc(name)+"?per_page=100", &rules); st == 200 {
		rulesOK = true
	}
	forbidForce, forbidDelete := false, false
	rulesets := map[int64]bool{}
	for _, r := range rules {
		rulesets[r.RulesetID] = true
		switch r.Type {
		case "non_fast_forward":
			forbidForce, b.Protected = true, true
		case "deletion":
			forbidDelete, b.Protected = true, true
		case "pull_request":
			b.Protected = true
			b.RequiredApprovals = max(b.RequiredApprovals, r.Parameters.Reviews)
			b.DismissStaleReviews = b.DismissStaleReviews || r.Parameters.DismissStale
			b.RequireCodeOwnerReviews = b.RequireCodeOwnerReviews || r.Parameters.CodeOwner
			b.RequireLastPushApproval = b.RequireLastPushApproval || r.Parameters.LastPush
		case "required_status_checks":
			b.Protected = true
			for _, ch := range r.Parameters.RequiredChecks {
				b.RequiredStatusChecks = append(b.RequiredStatusChecks, ch.Context)
			}
		case "required_signatures":
			b.Protected, b.RequireSignedCommits = true, true
		case "update", "required_linear_history", "creation", "required_deployments", "merge_queue":
			b.Protected = true
		}
	}
	ids := make([]int64, 0, len(rulesets))
	for id := range rulesets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		b.Sources = append(b.Sources, fmt.Sprintf("ruleset:%d", id))
		var rs struct {
			Bypass []struct {
				ActorID   *int64 `json:"actor_id"`
				ActorType string `json:"actor_type"`
				Mode      string `json:"bypass_mode"`
			} `json:"bypass_actors"`
		}
		if st, _ := c.get(rp+fmt.Sprintf("/rulesets/%d", id), &rs); st != 200 {
			continue
		}
		for _, a := range rs.Bypass {
			label := a.ActorType
			switch {
			case a.ActorType == "RepositoryRole" && a.ActorID != nil:
				label += ":" + firstNonEmptyStr(repositoryRoles[*a.ActorID], fmt.Sprint(*a.ActorID))
				if *a.ActorID == 5 {
					b.EnforceAdmins = false
				}
			case a.ActorID != nil:
				label += fmt.Sprintf(":%d", *a.ActorID)
			}
			b.BypassActors = append(b.BypassActors, label)
		}
	}

	var bp struct {
		Reviews *struct {
			Count        int  `json:"required_approving_review_count"`
			DismissStale bool `json:"dismiss_stale_reviews"`
			CodeOwners   bool `json:"require_code_owner_reviews"`
			LastPush     bool `json:"require_last_push_approval"`
		} `json:"required_pull_request_reviews"`
		Force struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_force_pushes"`
		Deletions struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_deletions"`
		Admins struct {
			Enabled bool `json:"enabled"`
		} `json:"enforce_admins"`
		Checks *struct {
			Contexts []string `json:"contexts"`
		} `json:"required_status_checks"`
		Signatures struct {
			Enabled bool `json:"enabled"`
		} `json:"required_signatures"`
	}
	classicKnown := false
	switch st, _ := c.get(rp+"/branches/"+esc(name)+"/protection", &bp); st {
	case 200:
		classicKnown, b.Protected = true, true
		b.Sources = append(b.Sources, "classic")
		forbidForce = forbidForce || !bp.Force.Enabled
		forbidDelete = forbidDelete || !bp.Deletions.Enabled
		b.EnforceAdmins = b.EnforceAdmins && bp.Admins.Enabled
		if bp.Reviews != nil {
			b.RequiredApprovals = max(b.RequiredApprovals, bp.Reviews.Count)
			b.DismissStaleReviews = b.DismissStaleReviews || bp.Reviews.DismissStale
			b.RequireCodeOwnerReviews = b.RequireCodeOwnerReviews || bp.Reviews.CodeOwners
			b.RequireLastPushApproval = b.RequireLastPushApproval || bp.Reviews.LastPush
		}
		if bp.Checks != nil {
			b.RequiredStatusChecks = append(b.RequiredStatusChecks, bp.Checks.Contexts...)
		}
		b.RequireSignedCommits = b.RequireSignedCommits || bp.Signatures.Enabled
	case 404:
		classicKnown = true // "Branch not protected"
	}
	b.AllowForcePushes = b.Protected && !forbidForce
	b.AllowDeletions = b.Protected && !forbidDelete
	// Report a state only when it is certain: protection seen anywhere is
	// certain; "unprotected" needs both sources read.
	if b.Protected || (rulesOK && classicKnown) {
		if !classicKnown && b.Protected {
			c.note("classic branch protection not readable; using rulesets only")
		}
		c.facts.Branches = map[string]*BranchFacts{name: b}
		c.mark(FactBranches)
		return
	}
	c.note("branch protection for %s not readable", name)
}

func firstNonEmptyStr(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func (c *collector) environments(rp string) {
	var resp struct {
		Environments []struct {
			Name            string `json:"name"`
			ProtectionRules []struct {
				Type              string `json:"type"`
				PreventSelfReview bool   `json:"prevent_self_review"`
				Reviewers         []any  `json:"reviewers"`
				WaitTimer         int    `json:"wait_timer"`
			} `json:"protection_rules"`
			BranchPolicy *struct {
				Protected bool `json:"protected_branches"`
				Custom    bool `json:"custom_branch_policies"`
			} `json:"deployment_branch_policy"`
		} `json:"environments"`
	}
	if st, _ := c.get(rp+"/environments?per_page=100", &resp); st != 200 {
		c.note("environments not readable")
		return
	}
	c.facts.Envs = map[string]*EnvFacts{}
	complete := true
	for _, e := range resp.Environments {
		env := &EnvFacts{Name: e.Name}
		for _, pr := range e.ProtectionRules {
			switch pr.Type {
			case "required_reviewers":
				env.RequiredReviewers += len(pr.Reviewers)
				env.PreventSelfReview = env.PreventSelfReview || pr.PreventSelfReview
			case "wait_timer":
				env.WaitTimer += pr.WaitTimer
			}
		}
		if bp := e.BranchPolicy; bp != nil {
			switch {
			case bp.Protected:
				env.BranchPolicy = "protected"
			case bp.Custom:
				env.BranchPolicy = "custom"
			}
		}
		var sec struct {
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if st, _ := c.get(rp+"/environments/"+esc(e.Name)+"/secrets?per_page=100", &sec); st == 200 {
			for _, s := range sec.Secrets {
				env.SecretNames = append(env.SecretNames, s.Name)
			}
		} else {
			complete = false
		}
		c.facts.Envs[e.Name] = env
	}
	if complete {
		c.mark(FactEnvironments)
	} else {
		c.note("environment secrets not readable (needs Secrets: read)")
	}
}

func (c *collector) secrets(rp string, r *RepoFacts) {
	var sec struct {
		Secrets []struct {
			Name      string `json:"name"`
			UpdatedAt string `json:"updated_at"`
		} `json:"secrets"`
	}
	if st, _ := c.get(rp+"/actions/secrets?per_page=100", &sec); st != 200 {
		c.note("Actions secrets not readable (needs Secrets: read)")
		return
	}
	for _, s := range sec.Secrets {
		r.SecretNames = append(r.SecretNames, s.Name)
		age := 0
		if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err == nil {
			age = int(c.opt.Now.Sub(t).Hours() / 24)
		}
		r.Secrets = append(r.Secrets, SecretFacts{Name: s.Name, AgeDays: age})
	}
	c.mark(FactSecrets)
}

func (c *collector) daysSince(s string) int {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return int(c.opt.Now.Sub(t).Hours() / 24)
}

func (c *collector) keysHooksCollaborators(rp string) {
	var keys []struct {
		ID        int64   `json:"id"`
		Title     string  `json:"title"`
		Key       string  `json:"key"`
		ReadOnly  bool    `json:"read_only"`
		Verified  bool    `json:"verified"`
		AddedBy   string  `json:"added_by"`
		CreatedAt string  `json:"created_at"`
		LastUsed  *string `json:"last_used"`
	}
	if st, _ := c.get(rp+"/keys?per_page=100", &keys); st == 200 {
		c.facts.DeployKeys = []DeployKeyFacts{}
		for _, k := range keys {
			dk := DeployKeyFacts{ID: k.ID, Title: k.Title, ReadOnly: k.ReadOnly, AgeDays: c.daysSince(k.CreatedAt), IdleDays: -1,
				AddedBy: k.AddedBy, Verified: k.Verified, PublicKey: k.Key}
			dk.CreatedAt, _ = time.Parse(time.RFC3339, k.CreatedAt)
			if k.LastUsed != nil && *k.LastUsed != "" {
				dk.IdleDays = c.daysSince(*k.LastUsed)
				dk.LastUsedAt, _ = time.Parse(time.RFC3339, *k.LastUsed)
			}
			c.facts.DeployKeys = append(c.facts.DeployKeys, dk)
		}
		c.mark(FactDeployKeys)
	}
	if hooks, ok := c.hooks(rp + "/hooks?per_page=100"); ok {
		c.facts.Webhooks = hooks
		c.mark(FactWebhooks)
	}
	var cols []struct {
		Login    string `json:"login"`
		RoleName string `json:"role_name"`
	}
	if st, _ := c.get(rp+"/collaborators?affiliation=outside&per_page=100", &cols); st == 200 {
		c.facts.Collaborators = []CollaboratorFacts{}
		for _, co := range cols {
			c.facts.Collaborators = append(c.facts.Collaborators, CollaboratorFacts{Login: co.Login, Permission: co.RoleName, Outside: true})
		}
		c.mark(FactCollaborators)
	}
}

// hooks reads a webhook list. Only the delivery host is kept: hook URLs
// often embed tokens in their path or query.
func (c *collector) hooks(p string) ([]WebhookFacts, bool) {
	var hooks []struct {
		ID     int64    `json:"id"`
		Active bool     `json:"active"`
		Events []string `json:"events"`
		Config struct {
			URL         string `json:"url"`
			InsecureSSL any    `json:"insecure_ssl"`
			Secret      string `json:"secret"`
		} `json:"config"`
	}
	if st, _ := c.get(p, &hooks); st != 200 {
		return nil, false
	}
	out := []WebhookFacts{}
	for _, h := range hooks {
		host := h.Config.URL
		plain := strings.HasPrefix(strings.ToLower(host), "http://")
		if u, err := url.Parse(h.Config.URL); err == nil && u.Host != "" {
			host = u.Host
		}
		out = append(out, WebhookFacts{ID: h.ID, URL: host, Active: h.Active, HasSecret: h.Config.Secret != "",
			InsecureSSL: fmt.Sprint(h.Config.InsecureSSL) == "1", Plaintext: plain, Events: h.Events})
	}
	return out, true
}

// codeOwnersPaths are where GitHub looks for CODEOWNERS, in its order.
var codeOwnersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

func (c *collector) files(rp, ref string) {
	sha := ref
	if !shaRe.MatchString(ref) {
		var cm struct {
			SHA string `json:"sha"`
		}
		if st, _ := c.get(rp+"/commits/"+esc(ref), &cm); st == 200 {
			sha = cm.SHA
		}
	}
	c.out.HeadSHA = sha
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int    `json:"size"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if st, _ := c.get(rp+"/git/trees/"+esc(sha)+"?recursive=1", &tree); st != 200 {
		c.note("repository tree not readable at %s", ref)
		return
	}
	if tree.Truncated {
		c.note("repository tree truncated by GitHub; deep action.yml files may be missed")
	}
	paths := map[string]bool{}
	var want []string
	for _, e := range tree.Tree {
		if e.Type != "blob" {
			continue
		}
		paths[e.Path] = true
		if IsWorkflowPath(e.Path) || (IsActionPath(e.Path) && (strings.HasPrefix(e.Path, ".github/") || !strings.Contains(e.Path, "/"))) {
			want = append(want, e.Path)
		}
	}
	sort.Strings(want)
	r := c.facts.Repo
	r.HasSecurityPolicy = boolPtr(paths["SECURITY.md"] || paths[".github/SECURITY.md"] || paths["docs/SECURITY.md"])
	r.HasDependabotConfig = boolPtr(paths[".github/dependabot.yml"] || paths[".github/dependabot.yaml"])
	c.mark(FactRepoFiles)

	has := false
	for _, p := range codeOwnersPaths {
		if paths[p] {
			has = true
			if raw, ok := c.blob(rp, p, ref); ok {
				c.facts.CodeOwners = ParseCodeOwners(string(raw))
				c.mark(FactCodeOwners)
			}
			break
		}
	}
	c.facts.HasCodeOwners = &has
	if !has {
		c.mark(FactCodeOwners)
	}

	if c.opt.SkipFiles {
		return
	}
	if len(want) > c.opt.MaxFiles {
		c.note("%d workflow/action files; reading the first %d", len(want), c.opt.MaxFiles)
		want = want[:c.opt.MaxFiles]
	}
	for _, p := range want {
		if raw, ok := c.blob(rp, p, sha); ok {
			c.out.Files[p] = raw
		} else {
			c.note("could not read %s", p)
		}
	}
}

func (c *collector) blob(rp, p, ref string) ([]byte, bool) {
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	segs := strings.Split(p, "/")
	for i := range segs {
		segs[i] = esc(segs[i])
	}
	if st, _ := c.get(rp+"/contents/"+strings.Join(segs, "/")+"?ref="+url.QueryEscape(ref), &f); st != 200 || f.Encoding != "base64" {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	return raw, err == nil
}

// ParseCodeOwners parses a CODEOWNERS file.
func ParseCodeOwners(s string) []CodeOwnersRule {
	var out []CodeOwnersRule
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		fields := strings.Fields(line)
		out = append(out, CodeOwnersRule{Pattern: fields[0], Owners: fields[1:], Line: i + 1})
	}
	return out
}

func (c *collector) org() {
	op := "/orgs/" + esc(c.opt.Org)
	var o struct {
		Login                  string `json:"login"`
		TwoFactor              *bool  `json:"two_factor_requirement_enabled"`
		DefaultPermission      string `json:"default_repository_permission"`
		MembersCanCreatePublic *bool  `json:"members_can_create_public_repositories"`
		WebSignoff             *bool  `json:"web_commit_signoff_required"`
	}
	if st, _ := c.get(op, &o); st != 200 {
		c.note("organisation %s not readable", c.opt.Org)
		return
	}
	of := &OrgFacts{Login: firstNonEmptyStr(o.Login, c.opt.Org), TwoFactorRequired: o.TwoFactor, DefaultRepositoryPermission: o.DefaultPermission,
		MembersCanCreatePublicRepos: o.MembersCanCreatePublic, WebCommitSignoffRequired: o.WebSignoff}
	if o.TwoFactor == nil {
		c.note("organisation security settings not visible (needs Organization administration: read)")
	}
	var ap struct {
		AllowedActions string `json:"allowed_actions"`
	}
	if st, _ := c.get(op+"/actions/permissions", &ap); st == 200 {
		of.AllowedActions = ap.AllowedActions
	}
	var wp struct {
		Default    string `json:"default_workflow_permissions"`
		CanApprove bool   `json:"can_approve_pull_request_reviews"`
	}
	if st, _ := c.get(op+"/actions/permissions/workflow", &wp); st == 200 {
		of.DefaultWorkflowPermissions, of.CanApprovePullRequestReviews = wp.Default, &wp.CanApprove
	}
	var sec struct {
		Secrets []struct {
			Name       string `json:"name"`
			Visibility string `json:"visibility"`
		} `json:"secrets"`
	}
	if st, _ := c.get(op+"/actions/secrets?per_page=100", &sec); st == 200 {
		for _, s := range sec.Secrets {
			of.Secrets = append(of.Secrets, OrgSecretFacts{Name: s.Name, Visibility: s.Visibility})
		}
	}
	if hooks, ok := c.hooks(op + "/hooks?per_page=100"); ok {
		of.Webhooks = hooks
	}
	c.facts.Org = of
	c.mark(FactOrg)

	var groups struct {
		Groups []struct {
			ID           int64  `json:"id"`
			Name         string `json:"name"`
			Visibility   string `json:"visibility"`
			AllowsPublic bool   `json:"allows_public_repositories"`
		} `json:"runner_groups"`
	}
	if st, _ := c.get(op+"/actions/runner-groups?per_page=100", &groups); st != 200 {
		c.note("runner groups not readable")
		return
	}
	for _, g := range groups.Groups {
		var runners struct {
			Total int `json:"total_count"`
		}
		n := 0
		if st, _ := c.get(op+fmt.Sprintf("/actions/runner-groups/%d/runners?per_page=1", g.ID), &runners); st == 200 {
			n = runners.Total
		} else if g.AllowsPublic {
			n = 1 // cannot count: assume it has runners rather than miss an open group
		}
		c.facts.RunnerGroups = append(c.facts.RunnerGroups, RunnerGroupFacts{Name: g.Name, Visibility: g.Visibility, AllowsPublicRepositories: g.AllowsPublic, SelfHostedRunners: n})
	}
	c.mark(FactRunnerGroups)
}

// actionRefs resolves every distinct remote uses: reference in the files.
func (c *collector) actionRefs() {
	type site struct {
		u    Uses
		line string
	}
	seen := map[string]site{}
	var order []string
	for p, raw := range c.out.Files {
		f, err := Parse(p, raw)
		if err != nil {
			continue
		}
		for _, j := range f.Jobs {
			vals := []*Value{j.Uses}
			for _, s := range j.Steps {
				vals = append(vals, s.Uses)
			}
			for _, v := range vals {
				if v == nil {
					continue
				}
				u := ParseUses(v.Text)
				if u.Kind != UsesRemote && u.Kind != UsesReusable {
					continue
				}
				if _, ok := seen[u.Raw]; !ok {
					seen[u.Raw] = site{u: u, line: f.Line(v.Pos.Line)}
					order = append(order, u.Raw)
				}
			}
		}
	}
	sort.Strings(order)
	if len(order) > c.opt.MaxActionRefs {
		c.note("%d distinct action references; resolving the first %d", len(order), c.opt.MaxActionRefs)
		order = order[:c.opt.MaxActionRefs]
	}
	c.facts.Actions = map[string]*ActionRefFacts{}
	repos := map[string]*repoState{}
	for _, raw := range order {
		s := seen[raw]
		c.facts.Actions[raw] = c.resolve(s.u, PinComment(s.line), repos)
	}
	c.mark(FactActionRefs)
}

type repoState struct {
	ok            bool
	status        int
	archived      bool
	redirected    string
	defaultBranch string
	lastPush      int
	tags          map[string]string // sha → tag
	branches      []string
}

func (c *collector) actionRepo(u Uses, cache map[string]*repoState) *repoState {
	key := u.Slug()
	if rs, ok := cache[key]; ok {
		return rs
	}
	rs := &repoState{}
	cache[key] = rs
	var info struct {
		FullName      string `json:"full_name"`
		Archived      bool   `json:"archived"`
		DefaultBranch string `json:"default_branch"`
		PushedAt      string `json:"pushed_at"`
	}
	st, _ := c.get("/repos/"+esc(u.Owner)+"/"+esc(u.Repo), &info)
	rs.status = st
	if st != 200 {
		return rs
	}
	rs.ok, rs.archived, rs.defaultBranch, rs.lastPush = true, info.Archived, info.DefaultBranch, c.daysSince(info.PushedAt)
	if !strings.EqualFold(info.FullName, u.Owner+"/"+u.Repo) {
		rs.redirected = info.FullName
	}
	return rs
}

func (c *collector) resolve(u Uses, comment string, cache map[string]*repoState) *ActionRefFacts {
	rf := &ActionRefFacts{Uses: u.Raw}
	rs := c.actionRepo(u, cache)
	ap := "/repos/" + esc(u.Owner) + "/" + esc(u.Repo)
	if !rs.ok {
		if rs.status == 404 {
			switch st, _ := c.get("/users/"+esc(u.Owner), nil); st {
			case 404:
				rf.OwnerMissing = true
			case 200:
				rf.RepoMissing = true
			}
		}
		return rf
	}
	rf.RepoArchived, rf.RedirectedTo, rf.LastPushDays = rs.archived, rs.redirected, rs.lastPush
	commitOf := func(ref string) string {
		var cm struct {
			SHA string `json:"sha"`
		}
		if st, _ := c.get(ap+"/commits/"+esc(ref), &cm); st == 200 {
			return cm.SHA
		}
		return ""
	}
	if !u.PinnedToSHA() {
		if u.Ref == "" {
			rf.RefType = "branch"
			return rf
		}
		switch {
		case c.statusOf(ap+"/git/ref/tags/"+esc(u.Ref)) == 200:
			rf.RefType = "tag"
		case c.statusOf(ap+"/git/ref/heads/"+esc(u.Ref)) == 200:
			rf.RefType = "branch"
		default:
			rf.RefType = "missing"
		}
		rf.SHA = commitOf(u.Ref)
	} else {
		rf.RefType, rf.SHA = "commit", u.Ref
		if comment != "" {
			rf.CommentRef = comment
			rf.CommentSHA = commitOf(comment)
		}
		rf.ReachableFromRepo = c.reachable(ap, u.Ref, rs)
	}
	if c.opt.Advisories != nil {
		ref := u.Ref
		if u.PinnedToSHA() && comment != "" {
			ref = comment
		}
		rf.Advisories = c.opt.Advisories(c.ctx, u.Action(), ref, rf.SHA)
	}
	return rf
}

func (c *collector) statusOf(p string) int {
	st, _ := c.get(p, nil)
	return st
}

// reachable decides whether sha belongs to the action repository rather than
// only to a fork in its network. It answers false only after ruling out the
// default branch, every listed tag, and the most recent branches; anything
// it cannot read leaves the answer unknown (nil).
func (c *collector) reachable(ap, sha string, rs *repoState) *bool {
	var cmp struct {
		Status string `json:"status"`
	}
	st, _ := c.get(ap+"/compare/"+esc(rs.defaultBranch)+"..."+esc(sha), &cmp)
	if st != 200 {
		return nil
	}
	if cmp.Status == "behind" || cmp.Status == "identical" {
		return boolPtr(true)
	}
	if rs.tags == nil {
		rs.tags = map[string]string{}
		var tags []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		if st, _ := c.get(ap+"/tags?per_page=100", &tags); st != 200 {
			return nil
		}
		for _, t := range tags {
			rs.tags[t.Commit.SHA] = t.Name
		}
		var branches []struct {
			Name string `json:"name"`
		}
		if st, _ := c.get(ap+"/branches?per_page=20", &branches); st != 200 {
			return nil
		}
		for _, b := range branches {
			rs.branches = append(rs.branches, b.Name)
		}
	}
	if _, ok := rs.tags[sha]; ok {
		return boolPtr(true)
	}
	for _, b := range rs.branches {
		if b == rs.defaultBranch {
			continue
		}
		var bc struct {
			Status string `json:"status"`
		}
		st, _ := c.get(ap+"/compare/"+esc(b)+"..."+esc(sha), &bc)
		if st != 200 {
			return nil
		}
		if bc.Status == "behind" || bc.Status == "identical" {
			return boolPtr(true)
		}
	}
	return boolPtr(false)
}
