package ghaudit

import (
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// applyEdits applies a fix's line edits bottom-up so earlier line numbers
// stay valid.
func applyEdits(src string, edits []Edit) string {
	lines := strings.Split(src, "\n")
	sort.Slice(edits, func(i, j int) bool { return edits[i].StartLine > edits[j].StartLine })
	for _, e := range edits {
		repl := strings.Split(e.Replacement, "\n")
		lines = append(lines[:e.StartLine-1], append(repl, lines[e.EndLine:]...)...)
	}
	return strings.Join(lines, "\n")
}

// TestInjectionFixProducesSafeValidWorkflow applies the generated fix and
// re-evaluates: the result must be valid YAML and the injection must be gone.
func TestInjectionFixProducesSafeValidWorkflow(t *testing.T) {
	cases := map[string]string{
		"block run, no env": `on: pull_request_target
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        run: |
          echo "${{ github.event.pull_request.title }}"
`,
		"inline run, no env": `on: pull_request_target
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`,
		"existing env": `on: issues
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        env:
          OTHER: x
        run: echo "${{ github.event.issue.body }}"
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			p := ".github/workflows/x.yml"
			rep := Evaluate(&Input{Files: map[string][]byte{p: []byte(src)}, RuleIDs: []string{"VNX-GH-001"}})
			if len(rep.Findings) != 1 {
				t.Fatalf("want 1 finding, got %d", len(rep.Findings))
			}
			fx := rep.Findings[0].Fix
			if fx == nil || len(fx.Edits) == 0 {
				t.Fatalf("no edits: %+v", fx)
			}
			fixed := applyEdits(src, fx.Edits)
			var n yaml.Node
			if err := yaml.Unmarshal([]byte(fixed), &n); err != nil {
				t.Fatalf("fixed workflow is not YAML: %v\n%s", err, fixed)
			}
			after := Evaluate(&Input{Files: map[string][]byte{p: []byte(fixed)}, RuleIDs: []string{"VNX-GH-001"}})
			if len(after.Findings) != 0 {
				t.Fatalf("injection still present after fix:\n%s", fixed)
			}
			if !strings.Contains(fixed, "env:") {
				t.Fatalf("env not declared:\n%s", fixed)
			}
		})
	}
}
