package ghaudit

// Facts is everything the engine can know about a repository and its
// organisation beyond the files themselves. Every field is optional: nil
// means "not collected", which is different from false/empty. Rules that
// need a fact declare it and report "unknown" rather than guessing when it is
// missing, and workflow rules use facts to lower or raise confidence.
//
// Facts is plain JSON so a collector (the CLI's API client, the webhook
// mirror) can cache it and replay an evaluation without calling GitHub.
type Facts struct {
	Repo     *RepoFacts                 `json:"repo,omitempty"`
	Org      *OrgFacts                  `json:"org,omitempty"`
	Branches map[string]*BranchFacts    `json:"branches,omitempty"` // by branch name
	Envs     map[string]*EnvFacts       `json:"environments,omitempty"`
	Actions  map[string]*ActionRefFacts `json:"actions,omitempty"` // by ParseUses(raw).Raw
	// CodeOwners is the parsed CODEOWNERS file: path pattern → owners. Nil
	// when not collected; empty when the repository has none.
	CodeOwners    []CodeOwnersRule    `json:"codeOwners,omitempty"`
	HasCodeOwners *bool               `json:"hasCodeOwners,omitempty"`
	DeployKeys    []DeployKeyFacts    `json:"deployKeys,omitempty"`
	Webhooks      []WebhookFacts      `json:"webhooks,omitempty"`
	Collaborators []CollaboratorFacts `json:"collaborators,omitempty"`
	RunnerGroups  []RunnerGroupFacts  `json:"runnerGroups,omitempty"`
	// Collected lists which fact groups were attempted, so "attempted and
	// empty" (no deploy keys) is distinguishable from "not collected".
	Collected map[string]bool `json:"collected,omitempty"`
}

// Has reports whether fact group g was collected.
func (f *Facts) Has(g string) bool { return f != nil && f.Collected[g] }

// Fact group names used in Facts.Collected and Rule.Requires.
const (
	FactRepo          = "repo"
	FactActionsPolicy = "actions_policy"
	FactBranches      = "branches"
	FactEnvironments  = "environments"
	FactActionRefs    = "action_refs"
	FactCodeOwners    = "codeowners"
	FactDeployKeys    = "deploy_keys"
	FactWebhooks      = "webhooks"
	FactCollaborators = "collaborators"
	FactOrg           = "org"
	FactRunnerGroups  = "runner_groups"
	FactSecurity      = "security_and_analysis"
	FactRepoFiles     = "repo_files"
	FactSecrets       = "secrets"
)

// RepoFacts is repository-level configuration.
type RepoFacts struct {
	FullName      string `json:"fullName"`
	Visibility    string `json:"visibility"` // public | private | internal
	DefaultBranch string `json:"defaultBranch"`
	Archived      bool   `json:"archived,omitempty"`
	Fork          bool   `json:"fork,omitempty"`
	AllowForking  *bool  `json:"allowForking,omitempty"`

	// Actions settings.
	ActionsEnabled               *bool    `json:"actionsEnabled,omitempty"`
	AllowedActions               string   `json:"allowedActions,omitempty"` // all | local_only | selected
	SHAPinningRequired           *bool    `json:"shaPinningRequired,omitempty"`
	AllowedActionPatterns        []string `json:"allowedActionPatterns,omitempty"`
	GithubOwnedAllowed           *bool    `json:"githubOwnedAllowed,omitempty"`
	VerifiedAllowed              *bool    `json:"verifiedAllowed,omitempty"`
	DefaultWorkflowPermissions   string   `json:"defaultWorkflowPermissions,omitempty"` // read | write
	CanApprovePullRequestReviews *bool    `json:"canApprovePullRequestReviews,omitempty"`
	// ForkPRApproval is the public-repo policy for running workflows from
	// fork pull requests: first_time_contributors_new_to_github |
	// first_time_contributors | all_external_contributors.
	ForkPRApproval string `json:"forkPrApproval,omitempty"`
	// Private-repo fork workflow settings.
	ForkPRWorkflowsEnabled *bool `json:"forkPrWorkflowsEnabled,omitempty"`
	ForkPRSendWriteTokens  *bool `json:"forkPrSendWriteTokens,omitempty"`
	ForkPRSendSecrets      *bool `json:"forkPrSendSecrets,omitempty"`
	ForkPRRequireApproval  *bool `json:"forkPrRequireApproval,omitempty"`

	// security_and_analysis.
	SecretScanning       *bool `json:"secretScanning,omitempty"`
	PushProtection       *bool `json:"pushProtection,omitempty"`
	DependabotUpdates    *bool `json:"dependabotSecurityUpdates,omitempty"`
	PrivateVulnReporting *bool `json:"privateVulnerabilityReporting,omitempty"`
	DependabotAlerts     *bool `json:"dependabotAlerts,omitempty"`

	// Repository files that are policy rather than code.
	HasSecurityPolicy   *bool `json:"hasSecurityPolicy,omitempty"`
	HasDependabotConfig *bool `json:"hasDependabotConfig,omitempty"`

	// Secrets are repository-level Actions secrets with their age; only
	// names and timestamps are ever read, never values.
	Secrets []SecretFacts `json:"secrets,omitempty"`

	// SecretNames are repository-level Actions secret names.
	SecretNames []string `json:"secretNames,omitempty"`
}

// Public reports whether the repository is public.
func (r *RepoFacts) Public() bool { return r != nil && r.Visibility == "public" }

// SecretFacts is one Actions secret's metadata.
type SecretFacts struct {
	Name    string `json:"name"`
	AgeDays int    `json:"ageDays"` // days since last update
}

// BranchFacts is the effective protection on one branch, merged from classic
// branch protection and every active ruleset that targets it.
type BranchFacts struct {
	Name                    string   `json:"name"`
	Protected               bool     `json:"protected"`
	RequiredApprovals       int      `json:"requiredApprovals"`
	DismissStaleReviews     bool     `json:"dismissStaleReviews"`
	RequireCodeOwnerReviews bool     `json:"requireCodeOwnerReviews"`
	RequireLastPushApproval bool     `json:"requireLastPushApproval"`
	AllowForcePushes        bool     `json:"allowForcePushes"`
	AllowDeletions          bool     `json:"allowDeletions"`
	EnforceAdmins           bool     `json:"enforceAdmins"`
	RequiredStatusChecks    []string `json:"requiredStatusChecks,omitempty"`
	RequireSignedCommits    bool     `json:"requireSignedCommits"`
	// BypassActors are ruleset bypass actors ("OrganizationAdmin",
	// "RepositoryRole:write", "Team:core", "Integration:12345").
	BypassActors []string `json:"bypassActors,omitempty"`
	// Sources records where protection came from ("classic", "ruleset:<id>").
	Sources []string `json:"sources,omitempty"`
}

// EnvFacts is one deployment environment.
type EnvFacts struct {
	Name              string `json:"name"`
	RequiredReviewers int    `json:"requiredReviewers"`
	PreventSelfReview bool   `json:"preventSelfReview"`
	WaitTimer         int    `json:"waitTimer"`
	// BranchPolicy: "" (any branch), protected, or custom.
	BranchPolicy string   `json:"branchPolicy,omitempty"`
	SecretNames  []string `json:"secretNames,omitempty"`
}

// Protected reports whether deploying to the environment needs a human or is
// restricted to protected branches.
func (e *EnvFacts) Protected() bool {
	return e != nil && (e.RequiredReviewers > 0 || e.BranchPolicy != "")
}

// ActionRefFacts is what resolving a `uses:` reference against GitHub found.
type ActionRefFacts struct {
	Uses string `json:"uses"`
	// SHA is the commit the ref resolves to now.
	SHA string `json:"sha,omitempty"`
	// RefType: branch | tag | commit | missing.
	RefType string `json:"refType,omitempty"`
	// CommentSHA is what the trailing version comment resolves to, for SHA
	// pins written as `@<sha> # v1.2.3`.
	CommentRef string `json:"commentRef,omitempty"`
	CommentSHA string `json:"commentSha,omitempty"`
	// ReachableFromRepo is false when a pinned SHA exists only in a fork of
	// the action repository (an impostor commit).
	ReachableFromRepo *bool            `json:"reachableFromRepo,omitempty"`
	RepoArchived      bool             `json:"repoArchived,omitempty"`
	RepoMissing       bool             `json:"repoMissing,omitempty"`
	OwnerMissing      bool             `json:"ownerMissing,omitempty"`
	RedirectedTo      string           `json:"redirectedTo,omitempty"` // renamed or transferred
	LatestRelease     string           `json:"latestRelease,omitempty"`
	LastPushDays      int              `json:"lastPushDays,omitempty"`
	Verified          bool             `json:"verifiedCreator,omitempty"`
	Advisories        []ActionAdvisory `json:"advisories,omitempty"`
}

// ActionAdvisory is a published vulnerability affecting the referenced version.
type ActionAdvisory struct {
	ID       string `json:"id"` // CVE or GHSA id
	Summary  string `json:"summary,omitempty"`
	Severity string `json:"severity,omitempty"`
	FixedIn  string `json:"fixedIn,omitempty"`
	URL      string `json:"url,omitempty"`
}

// CodeOwnersRule is one CODEOWNERS line.
type CodeOwnersRule struct {
	Pattern string   `json:"pattern"`
	Owners  []string `json:"owners"`
	Line    int      `json:"line"`
}

// DeployKeyFacts is one deploy key.
type DeployKeyFacts struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	ReadOnly bool   `json:"readOnly"`
	AgeDays  int    `json:"ageDays,omitempty"`
	// IdleDays is days since last use; -1 when GitHub has no record of use.
	IdleDays int `json:"idleDays"`
}

// WebhookFacts is one repository or organisation webhook.
type WebhookFacts struct {
	ID          int64    `json:"id"`
	URL         string   `json:"url"` // host only; never the full URL with tokens
	Active      bool     `json:"active"`
	HasSecret   bool     `json:"hasSecret"`
	InsecureSSL bool     `json:"insecureSsl"`
	Plaintext   bool     `json:"plaintext,omitempty"` // http:// delivery URL
	Events      []string `json:"events,omitempty"`
}

// CollaboratorFacts is one outside collaborator.
type CollaboratorFacts struct {
	Login      string `json:"login"`
	Permission string `json:"permission"` // read | triage | write | maintain | admin
	Outside    bool   `json:"outside"`
}

// RunnerGroupFacts is one organisation runner group.
type RunnerGroupFacts struct {
	Name                     string `json:"name"`
	Visibility               string `json:"visibility"` // all | selected | private
	AllowsPublicRepositories bool   `json:"allowsPublicRepositories"`
	SelfHostedRunners        int    `json:"selfHostedRunners"`
}

// OrgFacts is organisation-level configuration.
type OrgFacts struct {
	Login                        string `json:"login"`
	TwoFactorRequired            *bool  `json:"twoFactorRequired,omitempty"`
	DefaultRepositoryPermission  string `json:"defaultRepositoryPermission,omitempty"` // none | read | write | admin
	MembersCanCreatePublicRepos  *bool  `json:"membersCanCreatePublicRepos,omitempty"`
	MembersCanForkPrivateRepos   *bool  `json:"membersCanForkPrivateRepos,omitempty"`
	AllowedActions               string `json:"allowedActions,omitempty"`
	DefaultWorkflowPermissions   string `json:"defaultWorkflowPermissions,omitempty"`
	CanApprovePullRequestReviews *bool  `json:"canApprovePullRequestReviews,omitempty"`
	WebCommitSignoffRequired     *bool  `json:"webCommitSignoffRequired,omitempty"`
	// Secrets are org-level Actions secrets with their visibility.
	Secrets  []OrgSecretFacts `json:"secrets,omitempty"`
	Webhooks []WebhookFacts   `json:"webhooks,omitempty"`
}

// OrgSecretFacts is one organisation secret.
type OrgSecretFacts struct {
	Name       string `json:"name"`
	Visibility string `json:"visibility"` // all | private | selected
}
