// Package ghaudit is the Vulnetix GitHub posture engine: it evaluates GitHub
// Actions workflows, composite actions, action references, and repository and
// organisation settings, and reports misconfigurations as findings.
//
// It is pure: no network, no database. Callers collect Files and optional
// Facts (the CLI from the REST API, vdb-site from the webhook mirror), call
// Evaluate, and render the Report as SARIF or as Finding rows. Running the
// same engine on both sides is what keeps a CLI snapshot and an event-driven
// Software Factory finding identical for the same input.
package ghaudit

import (
	"sort"
	"strings"
)

// Task groups rules by what they analyse. Each is a CLI subcommand.
type Task string

const (
	TaskWorkflows Task = "workflows" // workflow and composite-action content
	TaskActions   Task = "actions"   // the actions and images a workflow runs
	TaskSettings  Task = "settings"  // repository configuration
	TaskOrg       Task = "org"       // organisation configuration
)

// AllTasks is every task, in report order.
var AllTasks = []Task{TaskWorkflows, TaskActions, TaskSettings, TaskOrg}

// ParseTask normalises a task name.
func ParseTask(s string) (Task, bool) {
	for _, t := range AllTasks {
		if strings.EqualFold(s, string(t)) {
			return t, true
		}
	}
	return "", false
}

// Severity vocabulary, aligned with sarif.Severity*.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "informational"
)

func (s Severity) rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// AtLeast reports whether s is at or above min.
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// ParseSeverity normalises a severity name ("" when unrecognised).
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium", "moderate":
		return Medium
	case "low":
		return Low
	case "info", "informational", "note":
		return Info
	}
	return ""
}

func (s Severity) down() Severity {
	switch s {
	case Critical:
		return High
	case High:
		return Medium
	case Medium:
		return Low
	}
	return Info
}

func (s Severity) up() Severity {
	switch s {
	case Info:
		return Low
	case Low:
		return Medium
	case Medium:
		return High
	}
	return Critical
}

// Confidence is how sure the rule is that the finding is exploitable as
// described, given what it could see.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rule is one check.
type Rule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Task        Task       `json:"task"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Summary     string     `json:"summary"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation"`
	CWE         []int      `json:"cwe,omitempty"`
	CAPEC       []string   `json:"capec,omitempty"`
	ATTACK      []string   `json:"attack,omitempty"`
	CWSS        string     `json:"cwss,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	References  []string   `json:"references,omitempty"`
	// Requires lists fact groups the rule cannot run without. Workflow rules
	// leave it empty and use facts only to refine.
	Requires []string `json:"requires,omitempty"`
	// Enhances lists fact groups that sharpen the rule when present.
	Enhances []string `json:"enhances,omitempty"`

	check func(*Context) []*Finding
}

// HelpURI is the rule's documentation page.
func (r *Rule) HelpURI() string {
	return "https://docs.cli.vulnetix.com/docs/github-rules/" + strings.ToLower(r.ID) + "/"
}

// Location is where a finding is. Settings findings have no Path; they carry
// a SettingsPath relative to the repository or organisation settings page.
type Location struct {
	Path         string `json:"path,omitempty"`
	StartLine    int    `json:"startLine,omitempty"`
	StartCol     int    `json:"startColumn,omitempty"`
	EndLine      int    `json:"endLine,omitempty"`
	Snippet      string `json:"snippet,omitempty"`
	Job          string `json:"job,omitempty"`
	Step         string `json:"step,omitempty"`
	SettingsPath string `json:"settingsPath,omitempty"`
	Scope        string `json:"scope,omitempty"` // repo | org | file
}

// Edit is one replacement in a file, by line range (inclusive).
type Edit struct {
	Path        string `json:"path"`
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine"`
	Replacement string `json:"replacement"`
}

// Fix is a suggested remediation the Software Factory can apply as a PR.
type Fix struct {
	Description string `json:"description"`
	Edits       []Edit `json:"edits,omitempty"`
	// Setting is a settings change ("actions.default_workflow_permissions=read")
	// for fixes that are not file edits.
	Setting string `json:"setting,omitempty"`
}

// Finding is one result.
type Finding struct {
	RuleID     string     `json:"ruleId"`
	Task       Task       `json:"task"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	// Subject is the finding's stable identity within the repository (or
	// organisation): the same misconfiguration keeps the same subject across
	// unrelated edits, so a re-evaluation updates rather than duplicates.
	Subject  string         `json:"subject"`
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	Location Location       `json:"location"`
	Evidence map[string]any `json:"evidence,omitempty"`
	// Adjustments explains how facts changed severity or confidence, in the
	// order applied ("repository is private and forking is disabled: −1").
	Adjustments []string `json:"adjustments,omitempty"`
	Fix         *Fix     `json:"fix,omitempty"`
	Fingerprint string   `json:"fingerprint"`

	delta int
}

// adjust moves severity by delta steps and records why. The move is applied
// in finalise, after the rule's default severity is known, so a rule can
// adjust before (or without) choosing a severity of its own.
func (f *Finding) adjust(delta int, why string) {
	f.delta += delta
	f.Adjustments = append(f.Adjustments, why)
}

func (f *Finding) applyDelta() {
	for ; f.delta > 0; f.delta-- {
		f.Severity = f.Severity.up()
	}
	for ; f.delta < 0; f.delta++ {
		f.Severity = f.Severity.down()
	}
}

// Coverage records that a rule was evaluated over a scope, so a caller can
// mark previously failing results in that scope as fixed.
type Coverage struct {
	RuleID string `json:"ruleId"`
	Scope  string `json:"scope"` // file path, "repo" or "org"
	State  string `json:"state"` // evaluated | unknown
	Reason string `json:"reason,omitempty"`
}

// Report is the outcome of Evaluate.
type Report struct {
	Findings []*Finding `json:"findings"`
	Coverage []Coverage `json:"coverage"`
	Rules    []*Rule    `json:"rules"`
	Errors   []string   `json:"errors,omitempty"`
	Notes    []string   `json:"notes,omitempty"`
}

var registry []*Rule

func register(r *Rule) *Rule {
	registry = append(registry, r)
	return r
}

// Rules returns every rule, ordered by ID.
func Rules() []*Rule {
	out := append([]*Rule{}, registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleByID returns the rule with the given ID, or nil.
func RuleByID(id string) *Rule {
	for _, r := range registry {
		if strings.EqualFold(r.ID, id) {
			return r
		}
	}
	return nil
}
