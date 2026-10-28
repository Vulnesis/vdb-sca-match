package ghaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Input is one evaluation request.
type Input struct {
	// Repository is owner/repo. Optional for an offline run over local files.
	Repository string
	Ref        string
	CommitSHA  string
	// Files maps repository-relative paths to content. Only workflow, action
	// metadata and CODEOWNERS files are read; others are ignored.
	Files map[string][]byte
	Facts *Facts
	// Tasks limits the run; empty means every task.
	Tasks []Task
	// RuleIDs limits the run to these rules; empty means every rule.
	RuleIDs []string
	// MinSeverity drops findings below it (after fact adjustments).
	MinSeverity Severity
}

// Context is what a rule's check sees.
type Context struct {
	In     *Input
	Facts  *Facts
	files  []*File
	byPath map[string]*File
	flows  map[*File]*flow
	rule   *Rule
}

// Files returns every parsed workflow and action file, ordered by path.
func (c *Context) Files() []*File { return c.files }

// Workflows returns the parsed workflow files.
func (c *Context) Workflows() []*File {
	var out []*File
	for _, f := range c.files {
		if f.Kind == KindWorkflow {
			out = append(out, f)
		}
	}
	return out
}

// Repo returns repository facts, or nil.
func (c *Context) Repo() *RepoFacts {
	if c.Facts == nil {
		return nil
	}
	return c.Facts.Repo
}

func (c *Context) flow(f *File) *flow {
	if fl, ok := c.flows[f]; ok {
		return fl
	}
	fl := newFlow(f, c)
	c.flows[f] = fl
	return fl
}

// localAction resolves a `uses: ./path` reference to its parsed action file.
func (c *Context) localAction(u Uses) *File {
	if c == nil || u.Kind != UsesLocal {
		return nil
	}
	dir := strings.TrimPrefix(path.Clean(u.Path), "./")
	for _, name := range []string{"action.yml", "action.yaml"} {
		if f := c.byPath[path.Join(dir, name)]; f != nil {
			return f
		}
	}
	return nil
}

// Evaluate runs the selected rules over the input.
func Evaluate(in *Input) *Report {
	ctx := &Context{In: in, Facts: in.Facts, byPath: map[string]*File{}, flows: map[*File]*flow{}}
	rep := &Report{}
	paths := make([]string, 0, len(in.Files))
	for p := range in.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		clean := strings.TrimPrefix(path.Clean("/"+p), "/")
		if !IsWorkflowPath(clean) && !IsActionPath(clean) {
			continue
		}
		f, err := Parse(clean, in.Files[p])
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			continue
		}
		ctx.files = append(ctx.files, f)
		ctx.byPath[clean] = f
	}

	tasks := map[Task]bool{}
	for _, t := range in.Tasks {
		tasks[t] = true
	}
	ids := map[string]bool{}
	for _, id := range in.RuleIDs {
		ids[strings.ToUpper(id)] = true
	}
	for _, r := range Rules() {
		if len(tasks) > 0 && !tasks[r.Task] {
			continue
		}
		if len(ids) > 0 && !ids[r.ID] {
			continue
		}
		rep.Rules = append(rep.Rules, r)
		scopes := ctx.scopesFor(r)
		if missing := missingFacts(in.Facts, r.Requires); len(missing) > 0 {
			for _, s := range scopes {
				rep.Coverage = append(rep.Coverage, Coverage{RuleID: r.ID, Scope: s, State: "unknown", Reason: "facts not collected: " + strings.Join(missing, ", ")})
			}
			continue
		}
		ctx.rule = r
		for _, f := range r.check(ctx) {
			ctx.finalise(r, f)
			if in.MinSeverity != "" && !f.Severity.AtLeast(in.MinSeverity) {
				continue
			}
			rep.Findings = append(rep.Findings, f)
		}
		for _, s := range scopes {
			rep.Coverage = append(rep.Coverage, Coverage{RuleID: r.ID, Scope: s, State: "evaluated"})
		}
	}
	rep.Findings = dedupe(rep.Findings)
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() > b.Severity.rank()
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	if len(ctx.files) == 0 && (len(tasks) == 0 || tasks[TaskWorkflows] || tasks[TaskActions]) {
		rep.Notes = append(rep.Notes, "no workflow or action files were found")
	}
	return rep
}

func (c *Context) scopesFor(r *Rule) []string {
	switch r.Task {
	case TaskSettings:
		return []string{"repo"}
	case TaskOrg:
		return []string{"org"}
	}
	out := make([]string, 0, len(c.files))
	for _, f := range c.files {
		out = append(out, f.Path)
	}
	return out
}

func missingFacts(f *Facts, req []string) []string {
	var out []string
	for _, g := range req {
		if !f.Has(g) {
			out = append(out, g)
		}
	}
	return out
}

func (c *Context) finalise(r *Rule, f *Finding) {
	f.RuleID, f.Task = r.ID, r.Task
	if f.Severity == "" {
		f.Severity = r.Severity
	}
	f.applyDelta()
	if f.Confidence == "" {
		f.Confidence = r.Confidence
	}
	if f.Title == "" {
		f.Title = r.Name
	}
	if f.Location.Scope == "" {
		switch {
		case f.Location.Path != "":
			f.Location.Scope = "file"
		case r.Task == TaskOrg:
			f.Location.Scope = "org"
		default:
			f.Location.Scope = "repo"
		}
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", strings.ToLower(c.In.Repository), r.ID, f.Subject)
	f.Fingerprint = hex.EncodeToString(h.Sum(nil))[:32]
}

func dedupe(fs []*Finding) []*Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f)
	}
	return out
}

// ── helpers used by rules ────────────────────────────────────────────────

// stepKey is a step's stable label: its id, else its name, else what it runs,
// else its index. Index is last because inserting a step renumbers the rest.
func stepKey(s *Step) string {
	switch {
	case s.ID != "":
		return s.ID
	case s.Name != "":
		return slug(s.Name)
	case s.Uses != nil:
		u := ParseUses(s.Uses.Text)
		if u.Kind == UsesDocker {
			return slug("docker-" + u.Image)
		}
		if u.Kind == UsesLocal {
			return slug(u.Path)
		}
		return slug(u.Action())
	}
	return fmt.Sprintf("steps[%d]", s.Index)
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '/' || r == '_' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// enclosing returns the job and step whose source span contains line.
func enclosing(f *File, line int) (*Job, *Step) {
	var job *Job
	for _, j := range f.Jobs {
		if j.Pos.Line <= line {
			job = j
		}
	}
	if job == nil {
		return nil, nil
	}
	var step *Step
	for _, s := range job.Steps {
		if s.Pos.Line <= line {
			step = s
		}
	}
	return job, step
}

// lineScope is a stable subject prefix for a line-level finding: the
// enclosing job/step, or the workflow when the line is outside any job.
func lineScope(f *File, line int) (string, *Job, *Step) {
	j, s := enclosing(f, line)
	switch {
	case j == nil:
		return "workflow", nil, nil
	case s == nil:
		return j.ID, j, nil
	}
	return j.ID + "/" + stepKey(s), j, s
}

func subject(f *File, parts ...string) string {
	return f.Path + "#" + strings.Join(parts, "/")
}

// at builds a file location from a position.
func at(f *File, p Pos, j *Job, s *Step) Location {
	l := Location{Path: f.Path, StartLine: p.Line, StartCol: p.Col, EndLine: p.Line, Snippet: strings.TrimSpace(f.Line(p.Line))}
	if j != nil {
		l.Job = j.ID
	}
	if s != nil {
		l.Step = stepKey(s)
	}
	return l
}

// writeScopes are permission scopes whose write grant matters for an attacker.
var writeScopes = []string{"actions", "checks", "contents", "deployments", "id-token", "issues", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses", "attestations", "discussions"}

// defaultWriteScopes is what the permissive repository default grants. It
// never includes id-token or attestations: those must be requested
// explicitly in a permissions: block.
var defaultWriteScopes = []string{"actions", "checks", "contents", "deployments", "issues", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses", "discussions"}

// effPerms is the token permission a job gets, and where it came from.
type effPerms struct {
	Write  []string // scopes with write
	Source string   // job | workflow | repository-default | unknown-default
	Known  bool     // false when it depends on an uncollected repository default
}

// effectivePermissions resolves the job token's permissions: job block, else
// workflow block, else the repository/organisation default.
func (c *Context) effectivePermissions(f *File, j *Job) effPerms {
	p, src := j.Permissions, "job"
	if p == nil {
		p, src = f.Permissions, "workflow"
	}
	if p == nil {
		if r := c.Repo(); r != nil && r.DefaultWorkflowPermissions != "" {
			if r.DefaultWorkflowPermissions == "write" {
				return effPerms{Write: append([]string{}, defaultWriteScopes...), Source: "repository-default", Known: true}
			}
			return effPerms{Source: "repository-default", Known: true}
		}
		if c.Facts != nil && c.Facts.Org != nil && c.Facts.Org.DefaultWorkflowPermissions == "read" {
			return effPerms{Source: "organisation-default", Known: true}
		}
		return effPerms{Write: []string{"contents", "packages"}, Source: "unknown-default", Known: false}
	}
	ep := effPerms{Source: src, Known: true}
	switch {
	case p.All == "write-all":
		ep.Write = append([]string{}, writeScopes...)
	case p.Scopes != nil:
		for _, s := range writeScopes {
			if p.Scopes[s] == "write" {
				ep.Write = append(ep.Write, s)
			}
		}
	}
	return ep
}

func (e effPerms) has(scope string) bool {
	for _, s := range e.Write {
		if s == scope {
			return true
		}
	}
	return false
}

// privilegedTriggers run with a write-capable token and secrets even when
// the triggering change comes from a fork.
var privilegedTriggers = []string{"pull_request_target", "workflow_run", "issue_comment", "issues", "discussion", "discussion_comment", "pull_request_review_comment", "pull_request_review"}

// privileged reports whether f runs in a privileged context reachable by
// outsiders, and names the trigger.
func privileged(f *File) (string, bool) {
	for _, t := range privilegedTriggers {
		if f.HasTrigger(t) {
			return t, true
		}
	}
	return "", false
}

// forkExposureReduced reports whether the repository's own configuration
// keeps outsiders from reaching fork-triggered paths, and explains why.
func (c *Context) forkExposureReduced() (string, bool) {
	r := c.Repo()
	if r == nil {
		return "", false
	}
	if r.Visibility != "public" && r.AllowForking != nil && !*r.AllowForking {
		return "repository is " + r.Visibility + " and forking is disabled, so only collaborators can open pull requests", true
	}
	return "", false
}

func boolp(b *bool) bool { return b != nil && *b }
