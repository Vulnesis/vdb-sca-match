package ghaudit

import (
	"regexp"
	"strings"
)

// Expr is one `${{ ... }}` occurrence inside a scalar.
type Expr struct {
	Raw    string // including the braces
	Body   string // trimmed inner text
	Offset int    // byte offset inside the scalar
}

var exprRe = regexp.MustCompile(`\$\{\{([\s\S]*?)\}\}`)

// Expressions returns every `${{ }}` occurrence in s.
func Expressions(s string) []Expr {
	var out []Expr
	for _, m := range exprRe.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, Expr{Raw: s[m[0]:m[1]], Body: strings.TrimSpace(s[m[2]:m[3]]), Offset: m[0]})
	}
	return out
}

// contextRefRe matches a context property path. Index syntax (`github['event']`)
// is normalised to dots before matching so it cannot be used to hide a source.
var contextRefRe = regexp.MustCompile(`\b(github|env|inputs|steps|needs|matrix|secrets|vars|jobs|job|runner|strategy)((?:\.[A-Za-z_*][\w*-]*|\[\*\]|\[\d+\])*)`)

var indexRe = regexp.MustCompile(`\[\s*'([^']*)'\s*\]|\[\s*"([^"]*)"\s*\]`)

// normaliseIndex rewrites `a['b']` to `a.b`.
func normaliseIndex(s string) string {
	return indexRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := indexRe.FindStringSubmatch(m)
		k := sub[1]
		if k == "" {
			k = sub[2]
		}
		return "." + k
	})
}

// UsesIndexSyntax reports whether body reads a context through string index
// syntax — legal, but a common way to slip a source past pattern matchers.
func UsesIndexSyntax(body string) bool { return indexRe.MatchString(body) }

// ContextRefs returns the context paths an expression body reads, lowercased.
func ContextRefs(body string) []string {
	body = normaliseIndex(body)
	var out []string
	for _, m := range contextRefRe.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.ToLower(m[1]+m[2]))
	}
	return out
}

// Source describes why a context path carries attacker-influenced text.
type Source struct {
	Path string `json:"path"`
	// Actor is who can set the value: "anyone" (any GitHub user, including
	// fork authors and issue openers), "writer" (someone with write access,
	// e.g. a workflow_dispatch input), or "caller" (whatever the calling
	// workflow passes in).
	Actor string `json:"actor"`
	// Triggers is the set of triggers that carry the field; empty means any.
	Triggers []string `json:"triggers,omitempty"`
	Why      string   `json:"why"`
}

type sourceRule struct {
	re       *regexp.Regexp
	actor    string
	triggers []string
	why      string
}

var (
	prTriggers      = []string{"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"}
	issueTriggers   = []string{"issues", "issue_comment"}
	commentTriggers = []string{"issue_comment", "pull_request_review_comment", "commit_comment", "discussion_comment"}
	pushTriggers    = []string{"push", "merge_group"}
)

func joinTriggers(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// sourceRules is the attacker-controlled field catalogue. Ordered most
// specific first. Numeric and hex fields (number, id, sha) are never sources.
var sourceRules = []sourceRule{
	{regexp.MustCompile(`^github\.head_ref$`), "anyone", prTriggers, "the pull request's head branch name is chosen by its author"},
	{regexp.MustCompile(`^github\.event\.pull_request\.(title|body)$`), "anyone", prTriggers, "pull request title and body are written by its author"},
	{regexp.MustCompile(`^github\.event\.pull_request\.head\.(ref|label)$`), "anyone", prTriggers, "the head branch name is chosen by the pull request author"},
	{regexp.MustCompile(`^github\.event\.pull_request\.head\.repo\.(default_branch|description|homepage)$`), "anyone", prTriggers, "fork repository metadata is controlled by the fork owner"},
	{regexp.MustCompile(`^github\.event\.pull_request\.user\.(login|name|email)$`), "anyone", prTriggers, "user profile fields are set by the user"},
	{regexp.MustCompile(`^github\.event\.issue\.(title|body)$`), "anyone", issueTriggers, "issue title and body are written by whoever opened it"},
	{regexp.MustCompile(`^github\.event\.(comment|review|review_comment)\.body$`), "anyone", joinTriggers(commentTriggers, []string{"pull_request_review"}), "comment and review bodies are written by any commenter"},
	{regexp.MustCompile(`^github\.event\.discussion\.(title|body)$`), "anyone", []string{"discussion", "discussion_comment"}, "discussion text is written by any participant"},
	{regexp.MustCompile(`^github\.event\.pages\.[^.]+\.page_name$`), "anyone", []string{"gollum"}, "wiki page names are written by wiki editors"},
	{regexp.MustCompile(`^github\.event\.(head_commit|commits\.[^.]+)\.(message|(author|committer)\.(name|email))$`), "anyone", pushTriggers, "commit metadata is written by the committer, including commits merged from forks"},
	{regexp.MustCompile(`^github\.event\.merge_group\.head_commit\.(message|(author|committer)\.(name|email))$`), "anyone", []string{"merge_group"}, "commit metadata is written by the committer"},
	{regexp.MustCompile(`^github\.event\.workflow_run\.(head_branch|display_title)$`), "anyone", []string{"workflow_run"}, "the triggering run's branch and title come from the (possibly forked) pull request"},
	{regexp.MustCompile(`^github\.event\.workflow_run\.head_commit\.(message|(author|committer)\.(name|email))$`), "anyone", []string{"workflow_run"}, "the triggering run's commit metadata is written by the committer"},
	{regexp.MustCompile(`^github\.event\.workflow_run\.pull_requests\.[^.]+\.head\.ref$`), "anyone", []string{"workflow_run"}, "the head branch name is chosen by the pull request author"},
	{regexp.MustCompile(`^github\.event\.release\.(name|body|tag_name)$`), "writer", []string{"release"}, "release text is written by a maintainer"},
	{regexp.MustCompile(`^github\.event\.inputs\.[^.]+$`), "writer", []string{"workflow_dispatch"}, "dispatch inputs are typed by whoever runs the workflow"},
	{regexp.MustCompile(`^github\.event\.client_payload(\..+)?$`), "writer", []string{"repository_dispatch"}, "repository_dispatch payloads are sent by any token holder"},
	{regexp.MustCompile(`^github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run)$`), "anyone", nil, "serialising the whole object includes its free-text fields"},
	{regexp.MustCompile(`^github\.event$`), "anyone", nil, "serialising the whole event payload includes every free-text field"},
}

// ClassifyContext returns the Source for a context path, if it is one.
func ClassifyContext(p string) (Source, bool) {
	p = strings.ToLower(p)
	for _, r := range sourceRules {
		if r.re.MatchString(p) {
			return Source{Path: p, Actor: r.actor, Triggers: r.triggers, Why: r.why}, true
		}
	}
	return Source{}, false
}

// reachable reports whether src can carry a value under any of f's triggers.
// A source that the workflow's triggers never populate is unreachable, so an
// issue-title expression in a push-only workflow is not reported.
func (s Source) reachable(f *File) bool {
	if len(s.Triggers) == 0 || f.Kind != KindWorkflow {
		return true
	}
	for _, t := range s.Triggers {
		if f.HasTrigger(t) {
			return true
		}
	}
	// workflow_call: the caller's event is forwarded, so any event field can
	// be present.
	return f.HasTrigger("workflow_call")
}

var comparisonRe = regexp.MustCompile(`==|!=|<=|>=|\s<\s|\s>\s`)

// sanitised reports whether the expression body turns its sources into a
// value that cannot carry shell syntax: a comparison, a boolean function, or
// a numeric conversion.
func sanitised(body string) bool {
	b := strings.ToLower(normaliseIndex(body))
	for _, fn := range []string{"contains(", "startswith(", "endswith(", "success(", "failure(", "always(", "cancelled(", "hashfiles("} {
		if strings.HasPrefix(b, fn) {
			return true
		}
	}
	if comparisonRe.MatchString(b) {
		return true
	}
	if strings.HasPrefix(b, "!") {
		return true
	}
	return false
}

// shellVarRe finds $VAR / ${VAR} references (and %VAR% for cmd, $env:VAR for pwsh).
var shellVarRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|\$env:([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%`)

// ShellVars returns the environment variable names a script line reads.
func ShellVars(line string) []string {
	var out []string
	for _, m := range shellVarRe.FindAllStringSubmatch(line, -1) {
		for _, g := range m[1:] {
			if g != "" {
				out = append(out, g)
			}
		}
	}
	return out
}
