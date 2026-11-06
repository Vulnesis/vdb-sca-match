package ghaudit

import (
	"fmt"
	"regexp"
	"strings"
)

// scriptInputs are `with:` keys whose value is executed as code by the named
// action, so an expression there is as dangerous as one in `run:`.
var scriptInputs = map[string][]string{
	"actions/github-script":             {"script"},
	"appleboy/ssh-action":               {"script"},
	"appleboy/scp-action":               {"script"},
	"azure/cli":                         {"inlinescript"},
	"azure/powershell":                  {"inlinescript"},
	"cloudflare/wrangler-action":        {"command", "precommands", "postcommands"},
	"nick-fields/retry":                 {"command"},
	"wretry/action":                     {"command"},
	"mathiasvr/command-output":          {"run"},
	"jannekem/run-python-script-action": {"script"},
}

// scriptSinks yields (text, position, label) for every place a step's text is
// executed: its run: script and any known script input.
func scriptSinks(s *Step) []struct {
	V     Value
	Label string
} {
	var out []struct {
		V     Value
		Label string
	}
	if s.Run != nil {
		out = append(out, struct {
			V     Value
			Label string
		}{*s.Run, "run"})
	}
	if s.Uses != nil {
		u := ParseUses(s.Uses.Text)
		for _, k := range scriptInputs[u.Slug()] {
			if v, ok := s.WithValue(k); ok {
				out = append(out, struct {
					V     Value
					Label string
				}{v, "with." + k})
			}
		}
	}
	return out
}

var _ = register(&Rule{
	ID: "VNX-GH-001", Name: "Untrusted input expanded into an executed script", Task: TaskWorkflows,
	Severity: Critical, Confidence: ConfidenceHigh, CWE: []int{94, 78}, CAPEC: []string{"CAPEC-242"}, ATTACK: []string{"T1059", "T1195.002"},
	CWSS:        "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "injection"},
	Summary:     "A ${{ }} expression carrying attacker-controlled text is substituted into a shell or script before it runs.",
	Description: "GitHub substitutes ${{ }} expressions into run: scripts (and script inputs such as actions/github-script's script) as text, before the interpreter parses them. Text that an outsider controls — a pull request title, a branch name, a comment, a commit message — becomes code that runs with the job's token and secrets. The engine follows the value through env:, GITHUB_ENV, step outputs, job outputs and local composite actions, and only reports sources the workflow's triggers can actually populate.",
	Remediation: "Pass the value through an environment variable and reference it as a shell variable (\"$TITLE\"), or as process.env in github-script, so it is data rather than code.",
	Enhances:    []string{FactRepo},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			if f.Kind != KindWorkflow && f.Kind != KindCompositeAction {
				continue
			}
			fl := c.flow(f)
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					env := fl.stepEnv[s]
					for _, sink := range scriptSinks(s) {
						for _, e := range Expressions(sink.V.Text) {
							t := fl.exprTaint(e.Body, j, env)
							if t == nil {
								continue
							}
							out = append(out, c.injectionFinding(f, j, s, sink.V, sink.Label, e, t))
						}
					}
					out = append(out, c.compositeInjection(f, fl, j, s, env)...)
				}
			}
		}
		return out
	},
})

// compositeInjection follows tainted with: values into a local composite
// action and reports the call site when the action expands that input into a
// script. The action file on its own can only say "an input reaches a shell";
// the call site knows the input is attacker-controlled.
func (c *Context) compositeInjection(f *File, fl *flow, j *Job, s *Step, env map[string]*Taint) []*Finding {
	if s.Uses == nil {
		return nil
	}
	lf := c.localAction(ParseUses(s.Uses.Text))
	if lf == nil || lf.Kind != KindCompositeAction {
		return nil
	}
	afl := c.flow(lf)
	var out []*Finding
	for _, kv := range s.With {
		t := fl.textTaint(kv.Value.Text, j, env)
		if t == nil {
			continue
		}
		input := "inputs." + strings.ToLower(kv.Key)
		for _, aj := range lf.Jobs {
			for _, as := range aj.Steps {
				for _, sink := range scriptSinks(as) {
					for _, e := range Expressions(sink.V.Text) {
						at := afl.exprTaint(e.Body, aj, afl.stepEnv[as])
						if at == nil || at.Source.Path != input {
							continue
						}
						chain := t.through("with." + kv.Key).through(lf.Path + " " + input)
						for _, hop := range at.Via {
							chain = chain.through(hop)
						}
						var src Expr
						for _, ce := range Expressions(kv.Value.Text) {
							if fl.exprTaint(ce.Body, j, env) != nil {
								src = ce
								break
							}
						}
						fd := c.injectionFinding(f, j, s, kv.Value, "with."+kv.Key, src, chain)
						fd.Subject = subject(f, j.ID, stepKey(s), "composite", strings.ToLower(kv.Key))
						fd.Evidence["action"] = lf.Path
						fd.Evidence["actionSink"] = lf.Path + ":" + fmt.Sprint(lf.Locate(sink.V.Pos.Line, e.Raw).Line)
						fd.Message = fmt.Sprintf("%s is passed as input %q to %s, which expands it into a script (%s); %s.", strings.TrimSpace(kv.Value.Text), kv.Key, lf.Path, e.Raw, t.Source.Why)
						fd.Fix = &Fix{Description: fmt.Sprintf("In %s, read the input through env: and reference it as a shell variable.", lf.Path)}
						out = append(out, fd)
					}
				}
			}
		}
	}
	return out
}

func (c *Context) injectionFinding(f *File, j *Job, s *Step, v Value, label string, e Expr, t *Taint) *Finding {
	from := v.Pos.Line
	p := f.Locate(from, e.Raw)
	fd := &Finding{
		Subject:  subject(f, j.ID, stepKey(s), label, strings.Join(ContextRefs(e.Body), "+")),
		Location: at(f, p, j, s),
		Evidence: map[string]any{"expression": e.Raw, "source": t.Source.Path, "actor": t.Source.Actor, "via": t.Via, "sink": label, "triggers": f.TriggerNames()},
	}
	chain := ""
	if len(t.Via) > 0 {
		chain = " via " + strings.Join(t.Via, " → ")
	}
	fd.Message = fmt.Sprintf("%s is expanded into %s of step %q in job %q%s; %s.", e.Raw, label, stepKey(s), j.ID, chain, t.Source.Why)
	switch t.Source.Actor {
	case "writer":
		fd.Severity, fd.Confidence = Medium, ConfidenceMedium
		fd.adjust(0, "source is only settable by users with write access")
	case "caller":
		fd.Severity, fd.Confidence = High, ConfidenceMedium
		fd.adjust(0, "source is an input; exploitability depends on what callers pass")
	}
	if t.Source.Actor == "anyone" {
		if _, ok := privileged(f); !ok && f.HasTrigger("pull_request") && f.Kind == KindWorkflow {
			// Unprivileged fork PR runs have a read-only token and no secrets;
			// the attacker still runs code, but mostly in their own sandbox.
			fd.adjust(-1, "pull_request from forks runs with a read-only token and no secrets")
		}
		if why, ok := c.forkExposureReduced(); ok {
			fd.adjust(-1, why)
			fd.Confidence = ConfidenceMedium
		}
	}
	fd.Fix = injectionFix(f, s, p, e)
	return fd
}

var envNameRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// injectionFix rewrites the expression to an environment variable reference
// on its line and declares that variable on the step, as one consistent pair
// of edits. Returns a description-only fix when the step's layout is not one
// it can edit safely (flow-style mappings, an env: written inline).
func injectionFix(f *File, s *Step, p Pos, e Expr) *Fix {
	name := envNameFor(e.Body)
	ref := "${" + name + "}"
	if s.Run == nil {
		ref = "process.env." + name
	}
	fix := &Fix{Description: fmt.Sprintf("Move %s into env.%s and reference it as %s.", e.Raw, name, ref)}
	for _, kv := range s.Env {
		if strings.EqualFold(kv.Key, name) {
			return fix // name collision: leave it to a human
		}
	}
	// Step keys share one indentation; the uses:/run: key line shows it.
	keyLine := 0
	switch {
	case s.Run != nil:
		keyLine = s.Run.Pos.Line
	case s.Uses != nil:
		keyLine = s.Uses.Pos.Line
	default:
		return fix
	}
	indent, ok := keyIndent(f.Line(keyLine))
	if !ok {
		return fix
	}
	declare := ""
	declLine := keyLine
	if len(s.Env) > 0 {
		first := s.Env[0].Value.Pos.Line
		envIndent, ok := keyIndent(f.Line(first))
		if !ok || first <= 0 {
			return fix
		}
		declLine = first
		declare = strings.Repeat(" ", envIndent) + name + ": " + e.Raw + "\n"
	} else {
		declare = strings.Repeat(" ", indent) + "env:\n" + strings.Repeat(" ", indent+2) + name + ": " + e.Raw + "\n"
	}
	// When the line the declaration goes above opens the sequence item
	// ("- run: ..."), the "- " marker moves up to the new first key.
	anchor := func(line string) string {
		if len(s.Env) > 0 {
			return declare + line
		}
		trimmed := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trimmed, "- ") {
			return declare + line
		}
		lead := line[:len(line)-len(trimmed)]
		return lead + "- " + strings.TrimLeft(declare, " ") + lead + "  " + strings.TrimLeft(trimmed[2:], " ")
	}
	rewritten := strings.Replace(f.Line(p.Line), e.Raw, ref, 1)
	if declLine == p.Line {
		fix.Edits = []Edit{{Path: f.Path, StartLine: p.Line, EndLine: p.Line, Replacement: anchor(rewritten)}}
		return fix
	}
	fix.Edits = []Edit{
		{Path: f.Path, StartLine: declLine, EndLine: declLine, Replacement: anchor(f.Line(declLine))},
		{Path: f.Path, StartLine: p.Line, EndLine: p.Line, Replacement: rewritten},
	}
	return fix
}

// keyIndent returns the column of a block-mapping key on line, accounting
// for a leading "- " sequence marker. Flow mappings are rejected.
func keyIndent(line string) (int, bool) {
	trimmed := strings.TrimLeft(line, " ")
	n := len(line) - len(trimmed)
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimLeft(trimmed[2:], " ")
		n = len(line) - len(trimmed)
	}
	if strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, ":") {
		return 0, false
	}
	return n, true
}

// envNameFor derives an environment variable name from the expression's
// first context path: github.event.pull_request.title → PULL_REQUEST_TITLE.
func envNameFor(body string) string {
	refs := ContextRefs(body)
	if len(refs) == 0 {
		return "UNTRUSTED_VALUE"
	}
	segs := strings.Split(refs[0], ".")
	last := segs[len(segs)-1]
	if len(segs) > 1 {
		switch last {
		case "body", "title", "ref", "message", "label", "name", "email":
			last = segs[len(segs)-2] + "_" + last
		}
	}
	name := strings.ToUpper(strings.Trim(envNameRe.ReplaceAllString(last, "_"), "_"))
	if name == "" {
		return "UNTRUSTED_VALUE"
	}
	return name
}

var envFileRe = regexp.MustCompile(`>>\s*["']?\$\{?(GITHUB_ENV|GITHUB_PATH)\}?["']?`)

var _ = register(&Rule{
	ID: "VNX-GH-002", Name: "Untrusted input written to GITHUB_ENV or GITHUB_PATH", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{77, 427}, ATTACK: []string{"T1574"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "injection"},
	Summary:     "Attacker-controlled text is appended to the job's environment or PATH file.",
	Description: "Lines appended to $GITHUB_ENV become environment variables for every later step, and lines appended to $GITHUB_PATH prepend directories to PATH. A value containing a newline can define LD_PRELOAD, NODE_OPTIONS, BASH_ENV or a new PATH entry, giving code execution in later steps even when those steps are written safely.",
	Remediation: "Do not write untrusted values to GITHUB_ENV/GITHUB_PATH. If a later step needs the value, pass it through a step output and env:, or use a random heredoc delimiter and validate the value first.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			fl := c.flow(f)
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Run == nil {
						continue
					}
					env := fl.stepEnv[s]
					for i, line := range strings.Split(s.Run.Text, "\n") {
						m := envFileRe.FindStringSubmatch(line)
						if m == nil {
							continue
						}
						t := fl.lineTaint(line, j, env)
						if t == nil {
							continue
						}
						p := f.Locate(s.Run.Pos.Line+boolInt(s.Run.Block)+i-1, strings.TrimSpace(line))
						fd := &Finding{
							Subject:  subject(f, j.ID, stepKey(s), strings.ToLower(m[1])),
							Location: at(f, p, j, s),
							Message:  fmt.Sprintf("Step %q in job %q writes %s (%s) to $%s.", stepKey(s), j.ID, t.Source.Path, t.Source.Why, m[1]),
							Evidence: map[string]any{"file": m[1], "source": t.Source.Path, "via": t.Via},
						}
						if t.Source.Actor == "writer" {
							fd.adjust(-1, "source is only settable by users with write access")
						}
						out = append(out, fd)
					}
				}
			}
		}
		return out
	},
})

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// untrustedCheckout reports whether a step checks out the triggering pull
// request's code (rather than the base branch) and names the ref expression.
func untrustedCheckout(s *Step) (string, bool) {
	if s.Uses != nil {
		u := ParseUses(s.Uses.Text)
		if u.Slug() == "actions/checkout" {
			for _, k := range []string{"ref", "repository"} {
				v, ok := s.WithValue(k)
				if !ok {
					continue
				}
				low := strings.ToLower(normaliseIndex(v.Text))
				for _, pat := range []string{"pull_request.head.", "github.head_ref", "workflow_run.head_", "refs/pull/", "merge_commit_sha", "steps.", "needs.", "head_sha", "head.sha", "head_branch"} {
					if strings.Contains(low, pat) {
						return v.Text, true
					}
				}
			}
		}
	}
	if s.Run != nil {
		low := strings.ToLower(s.Run.Text)
		for _, pat := range []string{"gh pr checkout", "git fetch origin pull/", "git fetch origin refs/pull/", "git checkout ${{ github.event.pull_request.head", "git checkout $head_sha", "refs/pull/${{"} {
			if strings.Contains(low, pat) {
				return strings.TrimSpace(s.Run.Text), true
			}
		}
	}
	return "", false
}

// executes reports whether a step after an untrusted checkout runs code from
// the workspace: any run: script, a local action, or a build tool action.
func executes(s *Step) bool {
	if s.Run != nil {
		return true
	}
	if s.Uses == nil {
		return false
	}
	u := ParseUses(s.Uses.Text)
	if u.Kind == UsesLocal {
		return true
	}
	switch u.Slug() {
	case "actions/setup-node", "actions/setup-python", "actions/setup-go", "actions/setup-java", "actions/upload-artifact", "actions/cache", "actions/checkout", "actions/download-artifact":
		return false
	}
	// Build/test/publish actions run the checked-out project's scripts.
	for _, k := range []string{"goreleaser/", "docker/build-push-action", "gradle/", "pnpm/", "bahmutov/npm-install", "cypress-io/", "pre-commit/", "golangci/golangci-lint-action", "ruby/setup-ruby"} {
		if strings.HasPrefix(u.Slug(), k) || u.Slug() == strings.TrimSuffix(k, "/") {
			return true
		}
	}
	return false
}

var _ = register(&Rule{
	ID: "VNX-GH-003", Name: "Privileged workflow runs code from an untrusted pull request", Task: TaskWorkflows,
	Severity: Critical, Confidence: ConfidenceHigh, CWE: []int{829, 94}, CAPEC: []string{"CAPEC-437"}, ATTACK: []string{"T1195.002"},
	CWSS:        "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "pwn-request", "supply-chain"},
	Summary:     "A pull_request_target, workflow_run or comment-triggered job checks out the pull request's code and then executes it.",
	Description: "pull_request_target, workflow_run and issue_comment run in the base repository's context: a write-capable GITHUB_TOKEN and every secret. Checking out the pull request head and then running a script, a build, or a local action executes code the pull request author wrote with those privileges. Build scripts, package manager hooks, test configuration and local actions all count as execution.",
	Remediation: "Split the work: run untrusted code under pull_request (no secrets, read-only token) and hand results to a privileged workflow as data via an artifact. If the privileged job must see the code, never execute it — and gate the job on an environment with required reviewers.",
	Enhances:    []string{FactRepo, FactEnvironments},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			trig, ok := privileged(f)
			if !ok {
				continue
			}
			for _, j := range f.Jobs {
				for i, s := range j.Steps {
					ref, ok := untrustedCheckout(s)
					if !ok {
						continue
					}
					var runner *Step
					for _, later := range j.Steps[i+1:] {
						if executes(later) {
							runner = later
							break
						}
					}
					fd := &Finding{
						Subject:  subject(f, j.ID, stepKey(s), "untrusted-checkout"),
						Location: at(f, s.Pos, j, s),
						Evidence: map[string]any{"trigger": trig, "checkoutRef": ref},
					}
					if runner == nil {
						fd.Severity, fd.Confidence = Medium, ConfidenceMedium
						fd.Message = fmt.Sprintf("Job %q (%s) checks out untrusted pull request code (%s). No later step obviously executes it, but any future step will run attacker code with the job's secrets.", j.ID, trig, ref)
					} else {
						fd.Evidence["executedBy"] = stepKey(runner)
						fd.Message = fmt.Sprintf("Job %q is triggered by %s, checks out untrusted pull request code (%s), and step %q then executes it with the base repository's token and secrets.", j.ID, trig, ref, stepKey(runner))
					}
					if why, ok := c.forkExposureReduced(); ok {
						fd.adjust(-2, why)
						fd.Confidence = ConfidenceLow
					}
					if j.Environment != "" && c.Facts != nil {
						if env := c.Facts.Envs[j.Environment]; env != nil && env.RequiredReviewers > 0 {
							fd.adjust(-1, fmt.Sprintf("job deploys to environment %q, which requires %d reviewer(s) before it runs", j.Environment, env.RequiredReviewers))
						}
					}
					out = append(out, fd)
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-004", Name: "Checkout credentials persisted into an uploaded workspace", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{522, 200},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "credential-exposure"},
	Summary:     "actions/checkout writes the token into .git/config and the workspace is then uploaded as an artifact.",
	Description: "By default actions/checkout stores the job's GITHUB_TOKEN in .git/config so later git commands authenticate. Uploading the checkout directory as an artifact publishes that token to anyone who can download the run's artifacts — on a public repository, everyone — while the job is still running.",
	Remediation: "Set persist-credentials: false on actions/checkout, and upload only the build output directory, never the repository root.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for _, j := range f.Jobs {
				var persisted *Step
				for _, s := range j.Steps {
					if s.Uses == nil {
						continue
					}
					u := ParseUses(s.Uses.Text)
					if u.Slug() == "actions/checkout" {
						if v, ok := s.WithValue("persist-credentials"); !ok || !strings.EqualFold(strings.TrimSpace(v.Text), "false") {
							persisted = s
						}
						continue
					}
					if persisted == nil || u.Slug() != "actions/upload-artifact" {
						continue
					}
					pv, _ := s.WithValue("path")
					if !uploadsWorkspace(pv.Text) {
						continue
					}
					fd := &Finding{
						Subject:  subject(f, j.ID, stepKey(s), "artifact-credentials"),
						Location: at(f, s.Pos, j, s),
						Message:  fmt.Sprintf("Step %q uploads %q while step %q left the checkout token in .git/config.", stepKey(s), strings.TrimSpace(pv.Text), stepKey(persisted)),
						Evidence: map[string]any{"checkout": stepKey(persisted), "path": pv.Text},
						Fix:      persistCredentialsFix(f, persisted),
					}
					if r := c.Repo(); r != nil && !r.Public() {
						fd.adjust(-1, "repository is not public, so artifacts are visible only to users with read access")
					}
					out = append(out, fd)
				}
			}
		}
		return out
	},
})

// persistCredentialsFix adds persist-credentials: false to a checkout step,
// under its existing with: block or in a new one.
func persistCredentialsFix(f *File, s *Step) *Fix {
	fix := &Fix{Description: "Set persist-credentials: false on the checkout step."}
	if len(s.With) > 0 {
		first := s.With[0].Value.Pos.Line
		ind, ok := keyIndent(f.Line(first))
		if !ok {
			return fix
		}
		fix.Edits = []Edit{{Path: f.Path, StartLine: first, EndLine: first, Replacement: strings.Repeat(" ", ind) + "persist-credentials: false\n" + f.Line(first)}}
		return fix
	}
	line := s.Uses.Pos.Line
	ind, ok := keyIndent(f.Line(line))
	if !ok {
		return fix
	}
	fix.Edits = []Edit{{Path: f.Path, StartLine: line, EndLine: line, Replacement: f.Line(line) + "\n" + strings.Repeat(" ", ind) + "with:\n" + strings.Repeat(" ", ind+2) + "persist-credentials: false"}}
	return fix
}

func uploadsWorkspace(p string) bool {
	for _, line := range strings.Split(p, "\n") {
		l := strings.TrimSpace(line)
		switch l {
		case ".", "./", "*", "**", "${{ github.workspace }}", "$GITHUB_WORKSPACE", "${{github.workspace}}", ".git", ".git/", "./.git":
			return true
		}
	}
	return false
}

var _ = register(&Rule{
	ID: "VNX-GH-005", Name: "Privileged workflow consumes artifacts from an untrusted run", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{494, 345}, ATTACK: []string{"T1195.002"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "artifact-poisoning"},
	Summary:     "A workflow_run job downloads artifacts produced by a fork-triggered run and extracts them into the workspace.",
	Description: "Artifacts uploaded by a pull_request run are written by the pull request's code. A workflow_run job that downloads them into the working directory lets that code overwrite scripts, configuration or binaries the privileged job then uses.",
	Remediation: "Download into a dedicated directory outside the workspace (e.g. ${{ runner.temp }}/artifacts), treat contents as untrusted data, and validate them before use. Never execute anything from the artifact.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			if !f.HasTrigger("workflow_run") {
				continue
			}
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Uses == nil {
						continue
					}
					u := ParseUses(s.Uses.Text)
					cross := false
					switch u.Slug() {
					case "actions/download-artifact":
						_, hasRun := s.WithValue("run-id")
						cross = hasRun
					case "dawidd6/action-download-artifact":
						cross = true
					}
					if !cross && s.Run != nil && strings.Contains(s.Run.Text, "gh run download") {
						cross = true
					}
					if !cross {
						continue
					}
					pv, _ := s.WithValue("path")
					dest := strings.TrimSpace(pv.Text)
					if strings.Contains(dest, "runner.temp") || strings.HasPrefix(dest, "/tmp") || strings.Contains(dest, "RUNNER_TEMP") {
						continue
					}
					if dest == "" {
						dest = "(workspace root)"
					}
					out = append(out, &Finding{
						Subject:  subject(f, j.ID, stepKey(s), "artifact-download"),
						Location: at(f, s.Pos, j, s),
						Message:  fmt.Sprintf("Job %q downloads artifacts from the triggering run into %s, where files written by untrusted pull request code can overwrite what the job executes.", j.ID, dest),
						Evidence: map[string]any{"action": u.Action(), "path": dest},
					})
				}
			}
		}
		return out
	},
})

var publishMarkers = []string{"npm publish", "yarn publish", "pnpm publish", "twine upload", "cargo publish", "gem push", "docker push", "goreleaser", "gh release", "mvn deploy", "gradle publish", "dotnet nuget push", "poetry publish"}

var publishActions = map[string]bool{
	"pypa/gh-action-pypi-publish": true, "goreleaser/goreleaser-action": true, "docker/build-push-action": true,
	"softprops/action-gh-release": true, "ncipollo/release-action": true, "js-devtools/npm-publish": true,
	"jreleaser/release-action": true, "actions/attest-build-provenance": true,
}

var cacheSetupActions = map[string]string{
	"actions/setup-node": "cache", "actions/setup-python": "cache", "actions/setup-go": "cache",
	"actions/setup-java": "cache", "actions/setup-dotnet": "cache", "pnpm/action-setup": "",
	"astral-sh/setup-uv": "enable-cache", "oven-sh/setup-bun": "",
}

var _ = register(&Rule{
	ID: "VNX-GH-006", Name: "Release workflow restores a cache writable by untrusted runs", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{349, 494}, ATTACK: []string{"T1195.002"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "cache-poisoning", "supply-chain"},
	Summary:     "A workflow that publishes releases restores dependency caches that other workflows on the default branch can write.",
	Description: "Caches are shared across workflows in the same branch scope. A compromised or injectable workflow on the default branch can save a poisoned cache entry that a release workflow later restores and ships inside a published artifact.",
	Remediation: "Disable caching in workflows that publish releases or sign artifacts (remove cache: / actions/cache), or use a cache key namespace no other workflow writes.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			release := f.HasTrigger("release")
			if t := f.Trigger("push"); t != nil && len(t.Tags) > 0 {
				release = true
			}
			publishes := false
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Uses != nil && publishActions[ParseUses(s.Uses.Text).Slug()] {
						publishes = true
					}
					if s.Run != nil {
						low := strings.ToLower(s.Run.Text)
						for _, m := range publishMarkers {
							if strings.Contains(low, m) {
								publishes = true
							}
						}
					}
				}
			}
			if !release && !publishes {
				continue
			}
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Uses == nil {
						continue
					}
					u := ParseUses(s.Uses.Text)
					cached := false
					if u.Slug() == "actions/cache" && u.Path != "save" {
						cached = true
					}
					if key, ok := cacheSetupActions[u.Slug()]; ok && key != "" {
						if v, ok := s.WithValue(key); ok && strings.TrimSpace(v.Text) != "" && !strings.EqualFold(strings.TrimSpace(v.Text), "false") {
							cached = true
						}
					}
					if u.Slug() == "actions/setup-go" {
						if v, ok := s.WithValue("cache"); !ok || !strings.EqualFold(strings.TrimSpace(v.Text), "false") {
							cached = true // setup-go caches by default since v4
						}
					}
					if !cached {
						continue
					}
					out = append(out, &Finding{
						Subject:  subject(f, j.ID, stepKey(s), "cache"),
						Location: at(f, s.Pos, j, s),
						Message:  fmt.Sprintf("Step %q restores a dependency cache in a workflow that publishes releases.", stepKey(s)),
						Evidence: map[string]any{"action": u.Action(), "releaseTrigger": release, "publishes": publishes},
					})
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-007", Name: "Workflow token permissions not declared", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceMedium, CWE: []int{250, 272},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "least-privilege"},
	Summary:     "Neither the workflow nor the job declares permissions:, so the token gets the repository default.",
	Description: "Without a permissions: block the GITHUB_TOKEN gets the repository or organisation default, which for many repositories is read/write on every scope. Any compromised step — a vulnerable action, an injection — can then push code, publish packages or approve pull requests.",
	Remediation: "Add `permissions: {}` (or `contents: read`) at the top of the workflow, and grant individual jobs only the scopes they need.",
	Enhances:    []string{FactRepo},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			if f.Permissions != nil {
				continue
			}
			for _, j := range f.Jobs {
				if j.Permissions != nil || j.Uses != nil {
					continue
				}
				ep := c.effectivePermissions(f, j)
				if ep.Known && len(ep.Write) == 0 {
					continue // repository default is read-only: nothing to grant
				}
				fd := &Finding{
					Subject:  subject(f, j.ID, "permissions"),
					Location: at(f, j.Pos, j, nil),
					Message:  fmt.Sprintf("Job %q declares no permissions and inherits the %s token permissions.", j.ID, strings.ReplaceAll(ep.Source, "-", " ")),
					Evidence: map[string]any{"source": ep.Source, "write": ep.Write},
					Fix: &Fix{Description: "Declare least-privilege permissions at the top of the workflow.", Edits: []Edit{{
						Path: f.Path, StartLine: firstJobsLine(f), EndLine: firstJobsLine(f), Replacement: "permissions:\n  contents: read\n\n" + f.Line(firstJobsLine(f)),
					}}},
				}
				if ep.Known {
					fd.Confidence = ConfidenceHigh
					fd.adjust(0, "repository default token permission is write")
				}
				if _, ok := privileged(f); ok {
					fd.adjust(1, "workflow runs on a trigger reachable by outsiders")
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

func firstJobsLine(f *File) int {
	for i, l := range f.Lines {
		if strings.HasPrefix(l, "jobs:") {
			return i + 1
		}
	}
	return 1
}

var _ = register(&Rule{
	ID: "VNX-GH-008", Name: "Excessive token permissions", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{250, 732},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "least-privilege"},
	Summary:     "The token is granted write-all, or write scopes at workflow level that every job inherits.",
	Description: "write-all grants every scope including actions, packages, pages and id-token. Workflow-level write scopes apply to every job, including jobs that run untrusted code or third-party actions.",
	Remediation: "Use `permissions: {}` at the workflow level and grant each job only the specific scopes it needs.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			_, priv := privileged(f)
			check := func(p *Permissions, scope string, j *Job) {
				if p == nil {
					return
				}
				var writes []string
				if p.All == "write-all" {
					writes = []string{"write-all"}
				} else {
					for _, s := range writeScopes {
						if p.Scopes[s] == "write" {
							writes = append(writes, s)
						}
					}
				}
				if len(writes) == 0 {
					return
				}
				// Job-level specific scopes are the recommended pattern; only
				// flag them when they are write-all or the job is privileged
				// and runs third-party code.
				if j != nil && p.All != "write-all" && !priv {
					return
				}
				if j == nil && p.All != "write-all" && len(f.Jobs) <= 1 {
					return
				}
				fd := &Finding{
					Subject:  subject(f, scope, "permissions"),
					Location: Location{Path: f.Path, StartLine: p.Pos.Line, EndLine: p.Pos.Line, Snippet: strings.TrimSpace(f.Line(p.Pos.Line))},
					Evidence: map[string]any{"write": writes, "level": map[bool]string{true: "workflow", false: "job"}[j == nil]},
				}
				grant := strings.Join(writes, ": write, ") + ": write"
				if p.All == "write-all" {
					grant = "write-all"
				}
				if j == nil {
					fd.Message = fmt.Sprintf("The workflow grants %s to all %d jobs.", grant, len(f.Jobs))
				} else {
					fd.Location.Job = j.ID
					fd.Message = fmt.Sprintf("Job %q grants %s.", j.ID, grant)
				}
				if p.All == "write-all" {
					fd.Severity = High
				}
				if priv {
					fd.adjust(1, "workflow runs on a trigger reachable by outsiders")
				}
				out = append(out, fd)
			}
			check(f.Permissions, "workflow", nil)
			for _, j := range f.Jobs {
				check(j.Permissions, j.ID, j)
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-009", Name: "OIDC token minted outside a protected environment", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceMedium, CWE: []int{285, 863},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "oidc", "cloud"},
	Summary:     "A job with id-token: write is not bound to an environment with reviewers or a branch policy.",
	Description: "id-token: write lets the job request an OIDC token that cloud providers exchange for credentials. Cloud trust policies commonly match on repository only; without an environment gate, any branch, and any code that can run in that job, can obtain cloud credentials.",
	Remediation: "Bind the job to an environment with required reviewers or a protected-branch policy, and scope the cloud trust policy's subject to that environment (repo:owner/name:environment:prod).",
	Enhances:    []string{FactEnvironments},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			for _, j := range f.Jobs {
				ep := c.effectivePermissions(f, j)
				if !ep.has("id-token") || !ep.Known {
					continue
				}
				fd := &Finding{Subject: subject(f, j.ID, "id-token"), Location: at(f, j.Pos, j, nil), Evidence: map[string]any{"environment": j.Environment}}
				switch {
				case j.Environment == "":
					fd.Message = fmt.Sprintf("Job %q can mint OIDC tokens and is not bound to any environment.", j.ID)
				case c.Facts.Has(FactEnvironments):
					env := c.Facts.Envs[j.Environment]
					if env.Protected() {
						continue
					}
					fd.Confidence = ConfidenceHigh
					fd.Message = fmt.Sprintf("Job %q can mint OIDC tokens in environment %q, which has no required reviewers and no branch policy.", j.ID, j.Environment)
				default:
					continue // bound to an environment we could not inspect
				}
				if _, ok := privileged(f); ok {
					fd.adjust(1, "workflow runs on a trigger reachable by outsiders")
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-010", Name: "All secrets passed to a reusable workflow", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{200, 668},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "secrets: inherit hands every repository, environment and organisation secret to the called workflow.",
	Description: "The called workflow receives every secret the caller can see, not just the ones it uses. A reusable workflow in another repository, or one pinned to a mutable ref, becomes a way to exfiltrate all of them.",
	Remediation: "Pass only the secrets the called workflow declares under on.workflow_call.secrets, by name.",
	Enhances:    []string{FactRepo},
	check: func(c *Context) []*Finding {
		var out []*Finding
		owner := strings.SplitN(c.In.Repository, "/", 2)[0]
		for _, f := range c.Workflows() {
			for _, j := range f.Jobs {
				if !j.SecretsInherit || j.Uses == nil {
					continue
				}
				u := ParseUses(j.Uses.Text)
				fd := &Finding{
					Subject:  subject(f, j.ID, "secrets-inherit"),
					Location: Location{Path: f.Path, StartLine: j.SecretsPos.Line, EndLine: j.SecretsPos.Line, Job: j.ID, Snippet: strings.TrimSpace(f.Line(j.SecretsPos.Line))},
					Message:  fmt.Sprintf("Job %q passes every secret to %s.", j.ID, j.Uses.Text),
					Evidence: map[string]any{"uses": j.Uses.Text},
				}
				switch {
				case u.Kind == UsesLocal:
					fd.adjust(-1, "called workflow is in this repository")
				case owner != "" && !strings.EqualFold(u.Owner, owner):
					fd.adjust(1, "called workflow belongs to a different owner")
				}
				if u.Kind == UsesReusable && !u.PinnedToSHA() {
					fd.adjust(1, "called workflow is referenced by a mutable ref")
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

var bulkSecretRe = regexp.MustCompile(`(?i)toJSON\(\s*secrets\s*\)|\bsecrets\s*\[\s*[^'"\]\s]|\$\{\{\s*secrets\s*\}\}`)

var _ = register(&Rule{
	ID: "VNX-GH-011", Name: "Secrets context exposed in bulk", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{200, 532},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "toJSON(secrets) or a computed secrets[...] index loads every secret into the job.",
	Description: "Secrets are only sent to a runner when referenced. toJSON(secrets) or a dynamic index forces every secret the workflow can see onto the runner, so a single compromised step can read all of them, and log masking is weaker for structured values.",
	Remediation: "Reference each secret by name, only in the step that needs it.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for i, line := range f.Lines {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				for _, e := range Expressions(line) {
					if !bulkSecretRe.MatchString(e.Raw) {
						continue
					}
					scope, j, st := lineScope(f, i+1)
					loc := at(f, Pos{Line: i + 1, Col: e.Offset + 1}, j, st)
					out = append(out, &Finding{
						Subject:  subject(f, scope, "bulk-secrets"),
						Location: loc,
						Message:  fmt.Sprintf("%s exposes every secret available to the workflow.", e.Raw),
						Evidence: map[string]any{"expression": e.Raw},
					})
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-012", Name: "Hard-coded container registry credentials", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{798},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "A job container or service declares a literal password instead of a secret reference.",
	Description: "Credentials written into the workflow file are visible to anyone who can read the repository and persist in git history.",
	Remediation: "Store the password as an Actions secret and reference it as ${{ secrets.NAME }}. Rotate the exposed credential.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			for _, j := range f.Jobs {
				cs := append([]*Container{}, j.Services...)
				if j.Container != nil {
					cs = append(cs, j.Container)
				}
				for _, ct := range cs {
					if ct.Password == nil || strings.TrimSpace(ct.Password.Text) == "" || len(Expressions(ct.Password.Text)) > 0 {
						continue
					}
					name := ct.Name
					if name == "" {
						name = "container"
					}
					out = append(out, &Finding{
						Subject:  subject(f, j.ID, name, "password"),
						Location: Location{Path: f.Path, StartLine: ct.Password.Pos.Line, EndLine: ct.Password.Pos.Line, Job: j.ID, Snippet: "password: ****"},
						Message:  fmt.Sprintf("Job %q %s %q has a literal registry password.", j.ID, map[bool]string{true: "container", false: "service"}[ct.Name == ""], name),
					})
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-013", Name: "Deprecated workflow commands re-enabled", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{77},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "injection"},
	Summary:     "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables ::set-env and ::add-path.",
	Description: "With this variable set, any process that prints to stdout — a test, a dependency, a log line containing user text — can set environment variables or PATH for later steps by printing a workflow command.",
	Remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV / $GITHUB_PATH instead.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			visit := func(kvs []KV, scope string) {
				for _, kv := range kvs {
					if strings.EqualFold(kv.Key, "ACTIONS_ALLOW_UNSECURE_COMMANDS") && !strings.EqualFold(strings.TrimSpace(kv.Value.Text), "false") {
						out = append(out, &Finding{
							Subject:  subject(f, scope, "insecure-commands"),
							Location: Location{Path: f.Path, StartLine: kv.Value.Pos.Line, EndLine: kv.Value.Pos.Line, Snippet: strings.TrimSpace(f.Line(kv.Value.Pos.Line))},
							Message:  "ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled in " + scope + ".",
						})
					}
				}
			}
			visit(f.Env, "workflow")
			for _, j := range f.Jobs {
				visit(j.Env, j.ID)
				for _, s := range j.Steps {
					visit(s.Env, j.ID+"/"+stepKey(s))
				}
			}
		}
		return out
	},
})

var botActorRe = regexp.MustCompile(`(?i)github\.(actor|triggering_actor)\s*==\s*'[^']*\[bot\]'|'[^']*\[bot\]'\s*==\s*github\.(actor|triggering_actor)`)

var _ = register(&Rule{
	ID: "VNX-GH-014", Name: "Authorisation by spoofable actor name", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{290, 863},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "authorisation"},
	Summary:     "An if: trusts github.actor == '<bot>[bot]' in a workflow outsiders can trigger.",
	Description: "github.actor is whoever caused the latest event, not who wrote the code. An attacker can open a pull request that a bot later updates (for example by asking Dependabot to rebase), making the bot the actor while the attacker's commits run with the privileges the check was meant to reserve for the bot.",
	Remediation: "Check the pull request author (github.event.pull_request.user.login) and that the head repository is the base repository, or use the bot's own metadata action.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			trig, ok := privileged(f)
			if !ok && !f.HasTrigger("pull_request") {
				continue
			}
			visit := func(v *Value, j *Job, s *Step) {
				if v == nil || !botActorRe.MatchString(v.Text) {
					return
				}
				scope := j.ID
				if s != nil {
					scope += "/" + stepKey(s)
				}
				fd := &Finding{
					Subject:  subject(f, scope, "actor-check"),
					Location: at(f, v.Pos, j, s),
					Message:  fmt.Sprintf("Condition %q authorises by github.actor, which an attacker can make a bot.", strings.TrimSpace(v.Text)),
					Evidence: map[string]any{"trigger": trig},
				}
				if !ok {
					fd.adjust(-1, "workflow is not privileged (pull_request only)")
				}
				out = append(out, fd)
			}
			for _, j := range f.Jobs {
				visit(j.If, j, nil)
				for _, s := range j.Steps {
					visit(s.If, j, s)
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-015", Name: "Condition always evaluates to true", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{570, 571, 697},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "logic"},
	Summary:     "An if: mixes ${{ }} with surrounding text, or is a block scalar, so it is a non-empty string and always true.",
	Description: "When an if: value contains text outside a single ${{ }} expression (including a trailing newline from a | block), GitHub evaluates the whole thing as a string, and any non-empty string is truthy. The guard — often an authorisation check — never blocks.",
	Remediation: "Write the condition as a single expression, either bare (if: a && b) or entirely inside one ${{ }}.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			visit := func(v *Value, j *Job, s *Step) {
				if v == nil {
					return
				}
				exprs := Expressions(v.Text)
				if len(exprs) == 0 {
					return
				}
				trimmed := strings.TrimSpace(v.Text)
				single := len(exprs) == 1 && exprs[0].Raw == trimmed
				if single && (!v.Block || !strings.HasSuffix(v.Text, "\n")) {
					return
				}
				scope := j.ID
				if s != nil {
					scope += "/" + stepKey(s)
				}
				out = append(out, &Finding{
					Subject:  subject(f, scope, "if"),
					Location: at(f, v.Pos, j, s),
					Message:  fmt.Sprintf("if: %q is evaluated as a non-empty string and is always true.", trimmed),
					Fix:      &Fix{Description: "Remove the ${{ }} wrapper and write a bare expression."},
				})
			}
			for _, j := range f.Jobs {
				visit(j.If, j, nil)
				for _, s := range j.Steps {
					visit(s.If, j, s)
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-016", Name: "Self-hosted runner reachable from pull requests", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{829, 668}, ATTACK: []string{"T1078"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "runners"},
	Summary:     "A job triggered by pull requests runs on a self-hosted runner.",
	Description: "Self-hosted runners are not ephemeral by default: code from a pull request can persist on the machine, read credentials from earlier jobs, and reach the internal network the runner sits on. On a public repository any GitHub user can trigger this.",
	Remediation: "Run pull request workflows on GitHub-hosted runners, or on ephemeral (just-in-time) self-hosted runners in an isolated runner group that public repositories cannot use.",
	Enhances:    []string{FactRepo, FactRunnerGroups},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			if !f.HasTrigger("pull_request", "pull_request_target", "issue_comment", "workflow_run") {
				continue
			}
			for _, j := range f.Jobs {
				if !selfHosted(j.RunsOn) {
					continue
				}
				fd := &Finding{
					Subject:  subject(f, j.ID, "runs-on"),
					Location: Location{Path: f.Path, StartLine: j.RunsOnPos.Line, EndLine: j.RunsOnPos.Line, Job: j.ID, Snippet: strings.TrimSpace(f.Line(j.RunsOnPos.Line))},
					Message:  fmt.Sprintf("Job %q runs on self-hosted runner %v and is reachable from pull requests.", j.ID, j.RunsOn),
					Evidence: map[string]any{"runsOn": j.RunsOn, "triggers": f.TriggerNames()},
				}
				if r := c.Repo(); r != nil {
					if r.Public() {
						fd.Confidence = ConfidenceHigh
						fd.adjust(1, "repository is public: any GitHub user can open a pull request")
					} else if why, ok := c.forkExposureReduced(); ok {
						fd.adjust(-1, why)
					}
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

func selfHosted(labels []string) bool {
	for _, l := range labels {
		ll := strings.ToLower(l)
		if ll == "self-hosted" || strings.HasPrefix(ll, "group:") {
			return true
		}
	}
	return false
}

var secretEchoRe = regexp.MustCompile(`(?i)\b(echo|printf|print|console\.log|write-host|cat)\b[^\n]*\$\{\{\s*secrets\.`)

// reachesLog reports whether a print command's output goes to the job log:
// not captured by $(...)/backticks, not piped on, not redirected to a file.
func reachesLog(line string) bool {
	i := secretEchoRe.FindStringIndex(line)
	if i == nil {
		return false
	}
	before, after := line[:i[0]], line[i[1]:]
	if strings.Count(before, "$(")-strings.Count(before, ")") > 0 || strings.Count(before, "`")%2 == 1 {
		return false
	}
	rest := after
	if j := strings.Index(rest, "}}"); j >= 0 {
		rest = rest[j+2:]
	}
	return !strings.ContainsAny(rest, "|>")
}

var _ = register(&Rule{
	ID: "VNX-GH-017", Name: "Secret printed to the job log", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceMedium, CWE: []int{532},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets"},
	Summary:     "A run: step prints a secret, relying on log masking to hide it.",
	Description: "Masking only redacts exact matches. Encoded, split or transformed output (base64, JSON, a substring, a multi-line value) is printed in clear to a log readable by everyone with read access.",
	Remediation: "Never print secrets. Pass them to tools through environment variables or files with restricted permissions.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Run == nil {
						continue
					}
					for i, line := range strings.Split(s.Run.Text, "\n") {
						if !secretEchoRe.MatchString(line) || !reachesLog(line) {
							continue
						}
						p := f.Locate(s.Run.Pos.Line+boolInt(s.Run.Block)+i-1, strings.TrimSpace(line))
						out = append(out, &Finding{
							Subject:  subject(f, j.ID, stepKey(s), "secret-echo"),
							Location: at(f, p, j, s),
							Message:  fmt.Sprintf("Step %q prints a secret to the log.", stepKey(s)),
						})
						break
					}
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-018", Name: "Comment-triggered workflow without an author check", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{862, 863},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "authorisation"},
	Summary:     "An issue_comment workflow runs privileged steps for any commenter.",
	Description: "issue_comment runs with a write token and secrets, and anyone who can comment can trigger it. A ChatOps command (/deploy, /release, /retest) without an author_association or permission check runs for every GitHub user on a public repository.",
	Remediation: "Gate the job on github.event.comment.author_association being OWNER, MEMBER or COLLABORATOR, or check the commenter's permission with the API before acting.",
	Enhances:    []string{FactRepo},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			if !f.HasTrigger("issue_comment") {
				continue
			}
			for _, j := range f.Jobs {
				// A dependent job is skipped when the job it needs is skipped,
				// so gating the root gates the chain: report roots only.
				if gated(j.If) || len(j.Needs) > 0 {
					continue
				}
				gatedStep := false
				for _, s := range j.Steps {
					if gated(s.If) || (s.Run != nil && strings.Contains(s.Run.Text, "collaborators/") && strings.Contains(s.Run.Text, "permission")) {
						gatedStep = true
						break
					}
					if s.Uses != nil && strings.Contains(ParseUses(s.Uses.Text).Slug(), "permission") {
						gatedStep = true
						break
					}
				}
				if gatedStep || len(j.Steps) == 0 {
					continue
				}
				fd := &Finding{
					Subject:  subject(f, j.ID, "comment-gate"),
					Location: at(f, j.Pos, j, nil),
					Message:  fmt.Sprintf("Job %q runs on issue_comment with no check of who commented.", j.ID),
				}
				ep := c.effectivePermissions(f, j)
				if ep.Known && len(ep.Write) == 0 {
					fd.adjust(-1, "job token is read-only")
				}
				if r := c.Repo(); r != nil && !r.Public() {
					fd.adjust(-1, "repository is not public, so only users with access can comment")
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

func gated(v *Value) bool {
	if v == nil {
		return false
	}
	low := strings.ToLower(v.Text)
	return strings.Contains(low, "author_association") || strings.Contains(low, "comment.user.login") || strings.Contains(low, "github.repository_owner")
}

var _ = register(&Rule{
	ID: "VNX-GH-019", Name: "Obfuscated action reference or expression", Task: TaskWorkflows,
	Severity: Low, Confidence: ConfidenceMedium, CWE: []int{656},
	CWSS:        "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "obfuscation"},
	Summary:     "A uses: path or ${{ }} expression is written in a form that hides what it resolves to.",
	Description: "uses: owner/repo/./@ref and github['event']['issue']['title'] resolve to the same thing as their plain forms but evade reviewers, allow-lists and simple scanners. Legitimate workflows rarely need them.",
	Remediation: "Write the reference or expression in its plain form.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for _, j := range f.Jobs {
				refs := []*Value{j.Uses}
				for _, s := range j.Steps {
					refs = append(refs, s.Uses)
				}
				for _, v := range refs {
					if v == nil || !ParseUses(v.Text).Obfuscated() {
						continue
					}
					out = append(out, &Finding{Subject: subject(f, j.ID, slug(v.Text), "obfuscated-uses"), Location: at(f, v.Pos, j, nil), Message: fmt.Sprintf("uses: %s contains path segments that hide the action it resolves to.", v.Text)})
				}
			}
			for i, line := range f.Lines {
				for _, e := range Expressions(line) {
					if UsesIndexSyntax(e.Body) {
						if _, ok := ClassifyContext(firstRef(e.Body)); ok {
							scope, j, st := lineScope(f, i+1)
							out = append(out, &Finding{Subject: subject(f, scope, "index-syntax", slug(firstRef(e.Body))), Location: at(f, Pos{Line: i + 1, Col: e.Offset + 1}, j, st), Message: fmt.Sprintf("%s reads an untrusted context through index syntax.", e.Raw)})
						}
					}
				}
			}
		}
		return out
	},
})

func firstRef(body string) string {
	if r := ContextRefs(body); len(r) > 0 {
		return r[0]
	}
	return ""
}

var _ = register(&Rule{
	ID: "VNX-GH-020", Name: "Pull request head ref used as a branch or tag name without quoting", Task: TaskWorkflows,
	Severity: Medium, Confidence: ConfidenceMedium, CWE: []int{88},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "argument-injection"},
	Summary:     "A shell variable holding the head branch name is passed to git or gh unquoted or without --.",
	Description: "Moving an untrusted value into env: fixes script injection, but `git checkout $BRANCH` still lets a branch named --upload-pack=... or -o... inject options. Branch names can start with a dash.",
	Remediation: "Quote the variable and end option parsing: git checkout -- \"$BRANCH\" (or git switch \"refs/heads/$BRANCH\").",
	check: func(c *Context) []*Finding {
		var out []*Finding
		argRe := regexp.MustCompile(`\b(git\s+(checkout|switch|fetch|push|pull|branch|tag|clone)|gh\s+pr\s+checkout)\b([^\n]*)`)
		for _, f := range c.Files() {
			fl := c.flow(f)
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Run == nil {
						continue
					}
					env := fl.stepEnv[s]
					for i, line := range strings.Split(s.Run.Text, "\n") {
						m := argRe.FindStringSubmatch(line)
						if m == nil || strings.Contains(m[3], " -- ") || strings.Contains(m[3], "refs/heads/") {
							continue
						}
						for _, v := range ShellVars(m[3]) {
							t := env[strings.ToUpper(v)]
							if t == nil || t.Source.Actor != "anyone" {
								continue
							}
							p := f.Locate(s.Run.Pos.Line+boolInt(s.Run.Block)+i-1, strings.TrimSpace(line))
							out = append(out, &Finding{
								Subject:  subject(f, j.ID, stepKey(s), "argument-"+strings.ToLower(v)),
								Location: at(f, p, j, s),
								Message:  fmt.Sprintf("$%s (from %s) is passed to %s without -- and can inject options.", v, t.Source.Path, m[1]),
								Evidence: map[string]any{"variable": v, "source": t.Source.Path},
							})
						}
					}
				}
			}
		}
		return out
	},
})

var (
	sendCmdRe = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|socat|invoke-webrequest|invoke-restmethod|iwr|irm|http|httpie)\b`)
	// captureHostRe matches hosts whose purpose is capturing requests, and
	// raw IPv4 addresses: sending a secret there has no legitimate reading.
	captureHostRe = regexp.MustCompile(`(?i)(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|beeceptor\.com|hookbin\.com|requestcatcher\.com|trycloudflare\.com|https?://\d{1,3}(\.\d{1,3}){3})`)
	envDumpRe     = regexp.MustCompile(`(?i)\b(printenv|env\b(\s*\|)|set\s*\|)|toJSON\(\s*(secrets|env)\s*\)|/proc/self/environ`)
	encodeRe      = regexp.MustCompile(`(?i)\b(base64|xxd|openssl\s+enc|gzip)\b`)
)

var _ = register(&Rule{
	ID: "VNX-GH-021", Name: "Secrets sent to an external host", Task: TaskWorkflows,
	Severity: Critical, Confidence: ConfidenceHigh, CWE: []int{200, 506}, ATTACK: []string{"T1552.001", "T1567"},
	CWSS:        "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "secrets", "exfiltration", "malicious"},
	Summary:     "A step sends the secrets context, the environment, or an encoded secret over the network, or sends any secret to a request-capture host or raw IP.",
	Description: "Token-theft campaigns add a step that dumps every secret (or the whole environment) and posts it to a server they control, often base64-encoded to slip past log masking, then remove the workflow. Authenticated calls that pass a single secret to an API are not reported; only bulk dumps, encoded secrets, and destinations with no legitimate use are.",
	Remediation: "Remove the step and treat every secret available to the workflow as compromised: rotate them, then review who added the change.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Run == nil {
						continue
					}
					secretVars := map[string]bool{}
					for _, kvs := range [][]KV{f.Env, j.Env, s.Env} {
						for _, kv := range kvs {
							if strings.Contains(kv.Value.Text, "secrets.") || bulkSecretRe.MatchString(kv.Value.Text) {
								secretVars[strings.ToUpper(kv.Key)] = true
							}
						}
					}
					text := s.Run.Text
					lines := strings.Split(text, "\n")
					hasSecret := func(l string) bool {
						if strings.Contains(l, "secrets.") || bulkSecretRe.MatchString(l) {
							return true
						}
						for _, v := range ShellVars(l) {
							if secretVars[strings.ToUpper(v)] {
								return true
							}
						}
						return false
					}
					for i, line := range lines {
						if !sendCmdRe.MatchString(line) {
							continue
						}
						why := ""
						switch {
						case envDumpRe.MatchString(line):
							why = "dumps the environment or every secret"
						case hasSecret(line) && captureHostRe.MatchString(line):
							why = "sends a secret to " + captureHostRe.FindString(line)
						case hasSecret(line) && encodeRe.MatchString(line):
							why = "encodes a secret and sends it"
						case i > 0 && encodeRe.MatchString(lines[i-1]) && hasSecret(lines[i-1]) && strings.Contains(line, "$"):
							why = "sends a secret encoded on the previous line"
						default:
							continue
						}
						p := f.Locate(s.Run.Pos.Line+boolInt(s.Run.Block)+i-1, strings.TrimSpace(line))
						out = append(out, &Finding{
							Subject:  subject(f, j.ID, stepKey(s), "exfiltration"),
							Location: at(f, p, j, s),
							Message:  fmt.Sprintf("Step %q %s over the network.", stepKey(s), why),
						})
						break
					}
				}
			}
		}
		return out
	},
})

var _ = register(&Rule{
	ID: "VNX-GH-022", Name: "Privileged job restores a cache keyed on contributor input", Task: TaskWorkflows,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{349, 494},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "cache-poisoning"},
	Summary:     "In a pull_request_target, workflow_run or comment-triggered job, a cache key or the cached content is derived from the pull request.",
	Description: "A key built from the head branch or head SHA lets a contributor choose which entry the privileged job restores; restoring a cache after checking out the pull request saves the contributor's files under a key later trusted runs restore.",
	Remediation: "Key caches only on base-branch content (hashFiles of the base checkout), and do not cache in a job that checked out untrusted code.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Workflows() {
			trig, ok := privileged(f)
			if !ok {
				continue
			}
			for _, j := range f.Jobs {
				untrusted := false
				for _, s := range j.Steps {
					if _, u := untrustedCheckout(s); u {
						untrusted = true
					}
					if s.Uses == nil {
						continue
					}
					u := ParseUses(s.Uses.Text)
					isCache := u.Slug() == "actions/cache"
					if key, ok := cacheSetupActions[u.Slug()]; ok && key != "" {
						if v, ok := s.WithValue(key); ok && !strings.EqualFold(strings.TrimSpace(v.Text), "false") && strings.TrimSpace(v.Text) != "" {
							isCache = true
						}
					}
					if !isCache {
						continue
					}
					key, _ := s.WithValue("key")
					restore, _ := s.WithValue("restore-keys")
					keyed := false
					for _, e := range Expressions(key.Text + restore.Text) {
						for _, ref := range ContextRefs(e.Body) {
							if src, ok := ClassifyContext(ref); ok && src.Actor == "anyone" {
								keyed = true
							}
							if strings.Contains(ref, "pull_request.head") || strings.Contains(ref, "workflow_run.head") || ref == "github.head_ref" {
								keyed = true
							}
						}
					}
					if !keyed && !untrusted {
						continue
					}
					why := "its key is derived from the pull request"
					if !keyed {
						why = "it runs after the pull request's code was checked out"
					}
					out = append(out, &Finding{
						Subject:  subject(f, j.ID, stepKey(s), "privileged-cache"),
						Location: at(f, s.Pos, j, s),
						Message:  fmt.Sprintf("Step %q caches in a %s job and %s.", stepKey(s), trig, why),
					})
				}
			}
		}
		return out
	},
})
