package ghaudit

import (
	"regexp"
	"strings"
)

// Taint is attacker-influenced data together with how it reached the point of
// use: a chain like ["env.TITLE", "steps.meta.outputs.branch"].
type Taint struct {
	Source Source   `json:"source"`
	Via    []string `json:"via,omitempty"`
}

func (t *Taint) through(hop string) *Taint {
	if t == nil {
		return nil
	}
	via := append(append([]string{}, t.Via...), hop)
	return &Taint{Source: t.Source, Via: via}
}

// stronger picks the taint with the wider actor set.
func stronger(a, b *Taint) *Taint {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if actorRank(b.Source.Actor) > actorRank(a.Source.Actor) {
		return b
	}
	return a
}

func actorRank(a string) int {
	switch a {
	case "anyone":
		return 3
	case "caller":
		return 2
	case "writer":
		return 1
	}
	return 0
}

// passThroughActions are actions whose outputs echo attacker-controlled text
// (usually the head branch name) without sanitising it. Keys are lowercase
// owner/repo; "*" means every output.
var passThroughActions = map[string][]string{
	"tj-actions/branch-names":                          {"*"},
	"xt0rted/pull-request-comment-branch":              {"head_ref", "*"},
	"actions-ecosystem/action-get-merged-pull-request": {"title", "body", "*"},
	"8bitjonny/gh-get-current-pr":                      {"pr_title", "pr_body", "*"},
	"jwalton/gh-find-current-pr":                       {"title", "body"},
	"potiuk/get-workflow-origin":                       {"sourceheadbranch", "sourceheadrepo"},
	"dawidd6/action-get-tag":                           {"tag"},
}

// flow holds the per-file taint state the rules query.
type flow struct {
	f          *File
	wfEnv      map[string]*Taint
	jobEnv     map[string]map[string]*Taint            // job → env name → taint
	stepEnv    map[*Step]map[string]*Taint             // effective env visible to the step
	stepOut    map[string]map[string]map[string]*Taint // job → step id → output → taint
	jobOut     map[string]map[string]*Taint            // job → output → taint
	inputTypes map[string]string
}

var (
	outputWriteRe = regexp.MustCompile(`(?i)echo\s+["']?([A-Za-z0-9_-]+)=(.*?)["']?\s*>>\s*["']?\$\{?GITHUB_OUTPUT\}?["']?`)
	envWriteRe    = regexp.MustCompile(`(?i)echo\s+["']?([A-Za-z_][A-Za-z0-9_]*)=(.*?)["']?\s*>>\s*["']?\$\{?GITHUB_ENV\}?["']?`)
)

func newFlow(f *File, ctx *Context) *flow {
	fl := &flow{
		f:          f,
		jobEnv:     map[string]map[string]*Taint{},
		stepEnv:    map[*Step]map[string]*Taint{},
		stepOut:    map[string]map[string]map[string]*Taint{},
		jobOut:     map[string]map[string]*Taint{},
		inputTypes: map[string]string{},
	}
	for _, in := range f.Inputs {
		fl.inputTypes[strings.ToLower(in.Name)] = strings.ToLower(in.Type)
	}
	fl.wfEnv = fl.envTaint(f.Env, nil, nil, "")
	// Jobs can read needs.<job>.outputs, so iterate to a fixpoint. Three
	// passes cover any realistic needs chain; the result is monotone.
	for pass := 0; pass < 3; pass++ {
		for _, j := range f.Jobs {
			fl.analyseJob(j, ctx)
		}
	}
	return fl
}

func (fl *flow) envTaint(kvs []KV, scope map[string]*Taint, j *Job, stepID string) map[string]*Taint {
	out := map[string]*Taint{}
	for k, v := range scope {
		out[k] = v
	}
	for _, kv := range kvs {
		if t := fl.textTaint(kv.Value.Text, j, out); t != nil {
			out[strings.ToUpper(kv.Key)] = t.through("env." + kv.Key)
		} else {
			delete(out, strings.ToUpper(kv.Key))
		}
	}
	return out
}

func (fl *flow) analyseJob(j *Job, ctx *Context) {
	env := fl.envTaint(j.Env, fl.wfEnv, j, "")
	fl.jobEnv[j.ID] = env
	if fl.stepOut[j.ID] == nil {
		fl.stepOut[j.ID] = map[string]map[string]*Taint{}
	}
	ghEnv := map[string]*Taint{}
	for _, s := range j.Steps {
		scope := map[string]*Taint{}
		for k, v := range env {
			scope[k] = v
		}
		for k, v := range ghEnv {
			scope[k] = v
		}
		se := fl.envTaint(s.Env, scope, j, s.ID)
		fl.stepEnv[s] = se
		if s.ID != "" {
			outs := fl.stepOut[j.ID][s.ID]
			if outs == nil {
				outs = map[string]*Taint{}
				fl.stepOut[j.ID][s.ID] = outs
			}
			if s.Uses != nil {
				ref := ParseUses(s.Uses.Text)
				if names, ok := passThroughActions[strings.ToLower(ref.Owner+"/"+ref.Repo)]; ok {
					src := Source{Path: "steps." + s.ID + ".outputs", Actor: "anyone", Why: ref.Owner + "/" + ref.Repo + " outputs attacker-controlled pull request text"}
					for _, n := range names {
						outs[strings.ToLower(n)] = &Taint{Source: src}
					}
				}
				if lf := ctx.localAction(ref); lf != nil {
					// A local composite action's outputs are tainted if its own
					// steps feed tainted data into them; approximated by any
					// tainted input being passed in.
					for _, kv := range s.With {
						if t := fl.textTaint(kv.Value.Text, j, se); t != nil {
							outs["*"] = t.through("uses " + s.Uses.Text)
						}
					}
				}
			}
		}
		if s.Run != nil {
			for _, line := range strings.Split(s.Run.Text, "\n") {
				if m := outputWriteRe.FindStringSubmatch(line); m != nil && s.ID != "" {
					if t := fl.lineTaint(m[2], j, se); t != nil {
						fl.stepOut[j.ID][s.ID][strings.ToLower(m[1])] = t.through("steps." + s.ID + ".outputs." + m[1])
					}
				}
				if m := envWriteRe.FindStringSubmatch(line); m != nil {
					if t := fl.lineTaint(m[2], j, se); t != nil {
						ghEnv[strings.ToUpper(m[1])] = t.through("GITHUB_ENV:" + m[1])
					}
				}
			}
		}
	}
	outs := map[string]*Taint{}
	for _, kv := range j.Outputs {
		if t := fl.textTaint(kv.Value.Text, j, env); t != nil {
			outs[strings.ToLower(kv.Key)] = t.through("needs." + j.ID + ".outputs." + kv.Key)
		}
	}
	fl.jobOut[j.ID] = outs
}

// lineTaint is textTaint plus shell variables: a value written to
// GITHUB_OUTPUT/GITHUB_ENV from $VAR carries VAR's taint.
func (fl *flow) lineTaint(text string, j *Job, env map[string]*Taint) *Taint {
	t := fl.textTaint(text, j, env)
	for _, v := range ShellVars(text) {
		if et := env[strings.ToUpper(v)]; et != nil {
			t = stronger(t, et)
		}
	}
	return t
}

// textTaint returns the strongest taint among the expressions in text.
func (fl *flow) textTaint(text string, j *Job, env map[string]*Taint) *Taint {
	var best *Taint
	for _, e := range Expressions(text) {
		best = stronger(best, fl.exprTaint(e.Body, j, env))
	}
	return best
}

// exprTaint returns the taint an expression body carries, or nil.
func (fl *flow) exprTaint(body string, j *Job, env map[string]*Taint) *Taint {
	if sanitised(body) {
		return nil
	}
	var best *Taint
	for _, ref := range ContextRefs(body) {
		best = stronger(best, fl.refTaint(ref, j, env))
	}
	return best
}

func (fl *flow) refTaint(ref string, j *Job, env map[string]*Taint) *Taint {
	if src, ok := ClassifyContext(ref); ok {
		if !src.reachable(fl.f) {
			return nil
		}
		if strings.HasPrefix(ref, "github.event.inputs.") {
			if typ := fl.inputTypes[strings.TrimPrefix(ref, "github.event.inputs.")]; typ == "boolean" || typ == "number" || typ == "choice" {
				return nil
			}
		}
		return &Taint{Source: src}
	}
	parts := strings.Split(ref, ".")
	switch parts[0] {
	case "env":
		if len(parts) >= 2 && env != nil {
			return env[strings.ToUpper(parts[1])]
		}
	case "inputs":
		if len(parts) < 2 {
			return nil
		}
		typ := fl.inputTypes[parts[1]]
		if typ == "boolean" || typ == "number" || typ == "choice" || typ == "environment" {
			return nil
		}
		switch {
		case fl.f.Kind == KindCompositeAction:
			return &Taint{Source: Source{Path: ref, Actor: "caller", Why: "action inputs carry whatever the calling workflow passes"}}
		case fl.f.HasTrigger("workflow_call"):
			return &Taint{Source: Source{Path: ref, Actor: "caller", Why: "reusable workflow inputs carry whatever the caller passes"}}
		case fl.f.HasTrigger("workflow_dispatch"):
			return &Taint{Source: Source{Path: ref, Actor: "writer", Why: "dispatch inputs are typed by whoever runs the workflow"}}
		}
	case "steps":
		if len(parts) >= 4 && parts[2] == "outputs" && j != nil {
			outs := fl.stepOut[j.ID][parts[1]]
			if t := outs[parts[3]]; t != nil {
				return t
			}
			return outs["*"]
		}
	case "needs":
		if len(parts) >= 4 && parts[2] == "outputs" {
			return fl.jobOut[parts[1]][parts[3]]
		}
	}
	return nil
}
