package ghaudit

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileKind is what a parsed file is: a workflow or one of the action shapes.
type FileKind string

const (
	KindWorkflow        FileKind = "workflow"
	KindCompositeAction FileKind = "composite-action"
	KindDockerAction    FileKind = "docker-action"
	KindNodeAction      FileKind = "node-action"
)

// Pos is a 1-based line/column inside the source file.
type Pos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// Value is a scalar from the source, kept with where it was written so a
// finding can point at the exact line instead of the enclosing step.
type Value struct {
	Text string `json:"text"`
	Pos  Pos    `json:"pos"`
	// Block is true for a literal (|) or folded (>) scalar, whose content
	// starts on the line after Pos.
	Block bool `json:"block,omitempty"`
	// Mapping/Sequence mark a non-scalar value; Text is then empty.
	Mapping  bool `json:"mapping,omitempty"`
	Sequence bool `json:"sequence,omitempty"`
}

// KV is one key of a mapping, in source order.
type KV struct {
	Key   string `json:"key"`
	Value Value  `json:"value"`
}

// Trigger is one entry under `on:`.
type Trigger struct {
	Name     string   `json:"name"`
	Types    []string `json:"types,omitempty"`
	Branches []string `json:"branches,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Pos      Pos      `json:"pos"`
}

// Permissions is a `permissions:` block. A nil *Permissions means the key is
// absent, which is not the same as `permissions: {}` (Empty, everything none).
type Permissions struct {
	All    string            `json:"all,omitempty"` // read-all | write-all
	Scopes map[string]string `json:"scopes,omitempty"`
	Empty  bool              `json:"empty,omitempty"`
	Pos    Pos               `json:"pos"`
}

// InputDecl is a workflow_dispatch / workflow_call / action input.
type InputDecl struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	Pos  Pos    `json:"pos"`
}

// Container is a job container or service.
type Container struct {
	Name     string `json:"name,omitempty"`
	Image    Value  `json:"image"`
	Username *Value `json:"username,omitempty"`
	Password *Value `json:"password,omitempty"`
}

// Step is one entry of a job's (or composite action's) steps.
type Step struct {
	Index      int    `json:"index"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Pos        Pos    `json:"pos"`
	If         *Value `json:"if,omitempty"`
	Uses       *Value `json:"uses,omitempty"`
	Run        *Value `json:"run,omitempty"`
	Shell      string `json:"shell,omitempty"`
	With       []KV   `json:"with,omitempty"`
	Env        []KV   `json:"env,omitempty"`
	WorkingDir string `json:"workingDirectory,omitempty"`
}

// WithValue returns the `with:` input named key.
func (s *Step) WithValue(key string) (Value, bool) {
	for _, kv := range s.With {
		if strings.EqualFold(kv.Key, key) {
			return kv.Value, true
		}
	}
	return Value{}, false
}

// Job is one entry under `jobs:`.
type Job struct {
	ID          string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Pos         Pos          `json:"pos"`
	If          *Value       `json:"if,omitempty"`
	RunsOn      []string     `json:"runsOn,omitempty"`
	RunsOnPos   Pos          `json:"runsOnPos"`
	Permissions *Permissions `json:"permissions,omitempty"`
	Env         []KV         `json:"env,omitempty"`
	Steps       []*Step      `json:"steps,omitempty"`
	Uses        *Value       `json:"uses,omitempty"` // reusable workflow call
	With        []KV         `json:"with,omitempty"`
	// SecretsInherit is `secrets: inherit`; Secrets is an explicit map.
	SecretsInherit bool         `json:"secretsInherit,omitempty"`
	SecretsPos     Pos          `json:"secretsPos"`
	Secrets        []KV         `json:"secrets,omitempty"`
	Needs          []string     `json:"needs,omitempty"`
	Outputs        []KV         `json:"outputs,omitempty"`
	Environment    string       `json:"environment,omitempty"`
	Container      *Container   `json:"container,omitempty"`
	Services       []*Container `json:"services,omitempty"`
}

// File is a parsed workflow or action metadata file.
type File struct {
	Path        string       `json:"path"`
	Kind        FileKind     `json:"kind"`
	Name        string       `json:"name,omitempty"`
	Triggers    []*Trigger   `json:"triggers,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
	Env         []KV         `json:"env,omitempty"`
	Jobs        []*Job       `json:"jobs,omitempty"`
	Inputs      []*InputDecl `json:"inputs,omitempty"`
	// Action-only fields.
	Using      string   `json:"using,omitempty"`
	ActionMain string   `json:"actionMain,omitempty"` // runs.image for docker actions
	Lines      []string `json:"-"`
}

// Trigger returns the named trigger, or nil.
func (f *File) Trigger(name string) *Trigger {
	for _, t := range f.Triggers {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// HasTrigger reports whether any of names is a trigger.
func (f *File) HasTrigger(names ...string) bool {
	for _, n := range names {
		if f.Trigger(n) != nil {
			return true
		}
	}
	return false
}

// Line returns source line n (1-based), or "".
func (f *File) Line(n int) string {
	if n < 1 || n > len(f.Lines) {
		return ""
	}
	return f.Lines[n-1]
}

// Locate finds the first line at or after from whose text contains needle.
// Expressions inside block scalars are located this way: yaml.v3 reports the
// block's indicator line, not each content line.
func (f *File) Locate(from int, needle string) Pos {
	if from < 1 {
		from = 1
	}
	for i := from; i <= len(f.Lines); i++ {
		if c := strings.Index(f.Lines[i-1], needle); c >= 0 {
			return Pos{Line: i, Col: c + 1}
		}
	}
	return Pos{Line: from, Col: 1}
}

// IsWorkflowPath reports whether p is a GitHub Actions workflow file.
func IsWorkflowPath(p string) bool {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if !strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml") {
		return false
	}
	return strings.HasPrefix(p, ".github/workflows/") && !strings.Contains(strings.TrimPrefix(p, ".github/workflows/"), "/")
}

// IsActionPath reports whether p is an action metadata file.
func IsActionPath(p string) bool {
	b := path.Base(p)
	return b == "action.yml" || b == "action.yaml"
}

// IsRelevantPath reports whether a change to p can change a posture result:
// workflows, action metadata and CODEOWNERS.
func IsRelevantPath(p string) bool {
	if IsWorkflowPath(p) || IsActionPath(p) {
		return true
	}
	switch strings.TrimPrefix(path.Clean("/"+p), "/") {
	case "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS":
		return true
	}
	return false
}

// Parse parses a workflow or action file. The kind is decided by the path
// first and the document shape second, so an action.yml outside .github still
// parses as an action.
func Parse(p string, content []byte) (*File, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	f := &File{Path: p, Lines: strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: not a YAML mapping", p)
	}
	root := doc.Content[0]
	if IsActionPath(p) || (mapGet(root, "runs") != nil && mapGet(root, "jobs") == nil) {
		parseAction(f, root)
		return f, nil
	}
	f.Kind = KindWorkflow
	if n := mapGet(root, "name"); n != nil {
		f.Name = n.Value
	}
	if v := mapGet(root, "on"); v != nil {
		f.Triggers = parseTriggers(v, f)
	}
	f.Permissions = parsePermissions(mapGetKV(root, "permissions"))
	f.Env = mapKVs(mapGet(root, "env"))
	if jobs := mapGet(root, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			f.Jobs = append(f.Jobs, parseJob(jobs.Content[i], jobs.Content[i+1]))
		}
	}
	return f, nil
}

func parseAction(f *File, root *yaml.Node) {
	if n := mapGet(root, "name"); n != nil {
		f.Name = n.Value
	}
	if in := mapGet(root, "inputs"); in != nil && in.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(in.Content); i += 2 {
			f.Inputs = append(f.Inputs, &InputDecl{Name: in.Content[i].Value, Pos: pos(in.Content[i])})
		}
	}
	runs := mapGet(root, "runs")
	using := ""
	if runs != nil {
		if u := mapGet(runs, "using"); u != nil {
			using = strings.ToLower(u.Value)
		}
	}
	f.Using = using
	switch using {
	case "composite":
		f.Kind = KindCompositeAction
		job := &Job{ID: "composite", Pos: pos(runs)}
		if steps := mapGet(runs, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for i, s := range steps.Content {
				job.Steps = append(job.Steps, parseStep(i, s))
			}
		}
		f.Jobs = []*Job{job}
	case "docker":
		f.Kind = KindDockerAction
		if img := mapGet(runs, "image"); img != nil {
			f.ActionMain = img.Value
		}
	default:
		f.Kind = KindNodeAction
	}
}

func parseTriggers(v *yaml.Node, f *File) []*Trigger {
	var out []*Trigger
	switch v.Kind {
	case yaml.ScalarNode:
		out = append(out, &Trigger{Name: v.Value, Pos: pos(v)})
	case yaml.SequenceNode:
		for _, n := range v.Content {
			out = append(out, &Trigger{Name: n.Value, Pos: pos(n)})
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(v.Content); i += 2 {
			t := &Trigger{Name: v.Content[i].Value, Pos: pos(v.Content[i])}
			body := v.Content[i+1]
			t.Types = scalarList(mapGet(body, "types"))
			t.Branches = scalarList(mapGet(body, "branches"))
			t.Tags = scalarList(mapGet(body, "tags"))
			if t.Name == "workflow_dispatch" || t.Name == "workflow_call" {
				if in := mapGet(body, "inputs"); in != nil && in.Kind == yaml.MappingNode {
					for j := 0; j+1 < len(in.Content); j += 2 {
						typ := ""
						if tn := mapGet(in.Content[j+1], "type"); tn != nil {
							typ = tn.Value
						}
						f.Inputs = append(f.Inputs, &InputDecl{Name: in.Content[j].Value, Type: typ, Pos: pos(in.Content[j])})
					}
				}
			}
			out = append(out, t)
		}
	}
	return out
}

func parsePermissions(k, v *yaml.Node) *Permissions {
	if v == nil {
		return nil
	}
	p := &Permissions{Pos: pos(k)}
	switch v.Kind {
	case yaml.ScalarNode:
		p.All = strings.ToLower(strings.TrimSpace(v.Value))
		if p.All == "" || v.Tag == "!!null" {
			p.All, p.Empty = "", true
		}
	case yaml.MappingNode:
		p.Scopes = map[string]string{}
		for i := 0; i+1 < len(v.Content); i += 2 {
			p.Scopes[v.Content[i].Value] = strings.ToLower(v.Content[i+1].Value)
		}
		if len(p.Scopes) == 0 {
			p.Empty = true
		}
	}
	return p
}

func parseJob(k, v *yaml.Node) *Job {
	j := &Job{ID: k.Value, Pos: pos(k)}
	if v.Kind != yaml.MappingNode {
		return j
	}
	if n := mapGet(v, "name"); n != nil {
		j.Name = n.Value
	}
	if n := mapGet(v, "if"); n != nil {
		val := value(n)
		j.If = &val
	}
	if rk, rv := mapGetKV(v, "runs-on"); rv != nil {
		j.RunsOnPos = pos(rk)
		switch rv.Kind {
		case yaml.ScalarNode:
			j.RunsOn = []string{rv.Value}
		case yaml.SequenceNode:
			j.RunsOn = scalarList(rv)
		case yaml.MappingNode:
			j.RunsOn = append(scalarList(mapGet(rv, "labels")), scalarList(mapGet(rv, "group"))...)
			if g := mapGet(rv, "group"); g != nil && g.Kind == yaml.ScalarNode {
				j.RunsOn = append(j.RunsOn, "group:"+g.Value)
			}
		}
	}
	j.Permissions = parsePermissions(mapGetKV(v, "permissions"))
	j.Env = mapKVs(mapGet(v, "env"))
	j.With = mapKVs(mapGet(v, "with"))
	j.Outputs = mapKVs(mapGet(v, "outputs"))
	j.Needs = scalarList(mapGet(v, "needs"))
	if n := mapGet(v, "uses"); n != nil {
		val := value(n)
		j.Uses = &val
	}
	if sk, sv := mapGetKV(v, "secrets"); sv != nil {
		j.SecretsPos = pos(sk)
		if sv.Kind == yaml.ScalarNode && strings.EqualFold(sv.Value, "inherit") {
			j.SecretsInherit = true
		} else {
			j.Secrets = mapKVs(sv)
		}
	}
	if n := mapGet(v, "environment"); n != nil {
		if n.Kind == yaml.MappingNode {
			if nn := mapGet(n, "name"); nn != nil {
				j.Environment = nn.Value
			}
		} else {
			j.Environment = n.Value
		}
	}
	if n := mapGet(v, "container"); n != nil {
		j.Container = parseContainer("", n)
	}
	if svc := mapGet(v, "services"); svc != nil && svc.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(svc.Content); i += 2 {
			j.Services = append(j.Services, parseContainer(svc.Content[i].Value, svc.Content[i+1]))
		}
	}
	if steps := mapGet(v, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
		for i, s := range steps.Content {
			j.Steps = append(j.Steps, parseStep(i, s))
		}
	}
	return j
}

func parseContainer(name string, n *yaml.Node) *Container {
	c := &Container{Name: name}
	if n.Kind == yaml.ScalarNode {
		c.Image = value(n)
		return c
	}
	if img := mapGet(n, "image"); img != nil {
		c.Image = value(img)
	}
	if cr := mapGet(n, "credentials"); cr != nil {
		if u := mapGet(cr, "username"); u != nil {
			val := value(u)
			c.Username = &val
		}
		if p := mapGet(cr, "password"); p != nil {
			val := value(p)
			c.Password = &val
		}
	}
	return c
}

func parseStep(i int, n *yaml.Node) *Step {
	s := &Step{Index: i, Pos: pos(n)}
	if n.Kind != yaml.MappingNode {
		return s
	}
	for k := 0; k+1 < len(n.Content); k += 2 {
		key, v := n.Content[k], n.Content[k+1]
		switch key.Value {
		case "id":
			s.ID = v.Value
		case "name":
			s.Name = v.Value
		case "if":
			val := value(v)
			s.If = &val
		case "uses":
			val := value(v)
			s.Uses = &val
		case "run":
			val := value(v)
			s.Run = &val
		case "shell":
			s.Shell = v.Value
		case "with":
			s.With = mapKVs(v)
		case "env":
			s.Env = mapKVs(v)
		case "working-directory":
			s.WorkingDir = v.Value
		}
	}
	return s
}

// ── yaml.Node helpers ─────────────────────────────────────────────────────

func pos(n *yaml.Node) Pos { return Pos{Line: n.Line, Col: n.Column} }

func value(n *yaml.Node) Value {
	v := Value{Pos: pos(n)}
	switch n.Kind {
	case yaml.ScalarNode:
		v.Text = n.Value
		v.Block = n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	case yaml.MappingNode:
		v.Mapping = true
	case yaml.SequenceNode:
		v.Sequence = true
	case yaml.AliasNode:
		if n.Alias != nil {
			return value(n.Alias)
		}
	}
	return v
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	_, v := mapGetKV(n, key)
	return v
}

func mapGetKV(n *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			v := n.Content[i+1]
			if v.Kind == yaml.AliasNode && v.Alias != nil {
				v = v.Alias
			}
			return n.Content[i], v
		}
	}
	return nil, nil
}

func mapKVs(n *yaml.Node) []KV {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]KV, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, KV{Key: n.Content[i].Value, Value: value(n.Content[i+1])})
	}
	return out
}

func scalarList(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		out := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, c.Value)
			}
		}
		return out
	}
	return nil
}

// TriggerNames returns the file's trigger names, sorted.
func (f *File) TriggerNames() []string {
	out := make([]string, 0, len(f.Triggers))
	for _, t := range f.Triggers {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}
