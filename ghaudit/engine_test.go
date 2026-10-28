package ghaudit

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite expect.txt from current results")

// TestCases runs every testdata/cases/<name> directory through Evaluate and
// compares the complete finding list with expect.txt. The comparison is exact
// in both directions, so a fixture proves the absence of false positives as
// much as the presence of true ones.
//
// Each case directory holds repository files at their real paths, an
// optional facts.json, an optional repo.txt (owner/name), and expect.txt with
// one "RULE severity path:line subject" line per finding.
func TestCases(t *testing.T) {
	dirs, err := filepath.Glob("testdata/cases/*")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, dir := range dirs {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			in := loadCase(t, dir)
			rep := Evaluate(in)
			if len(rep.Errors) > 0 {
				t.Fatalf("parse errors: %v", rep.Errors)
			}
			checkFixes(t, in, rep)
			got := render(rep)
			want, _ := os.ReadFile(filepath.Join(dir, "expect.txt"))
			if *update {
				if err := os.WriteFile(filepath.Join(dir, "expect.txt"), []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			if strings.TrimSpace(got) != strings.TrimSpace(string(want)) {
				t.Errorf("findings mismatch\n--- want\n%s\n--- got\n%s", want, got)
			}
		})
	}
}

func loadCase(t *testing.T, dir string) *Input {
	t.Helper()
	in := &Input{Files: map[string][]byte{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		switch rel {
		case "expect.txt":
		case "repo.txt":
			in.Repository = strings.TrimSpace(string(b))
		case "facts.json":
			in.Facts = &Facts{}
			if err := json.Unmarshal(b, in.Facts); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		default:
			in.Files[rel] = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if in.Repository == "" {
		in.Repository = "acme/app"
	}
	return in
}

func render(rep *Report) string {
	lines := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		where := f.Location.Path
		if where == "" {
			where = f.Location.SettingsPath
		} else {
			where = fmt.Sprintf("%s:%d", where, f.Location.StartLine)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s", f.RuleID, f.Severity, where, f.Subject))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

// checkFixes applies every edit-carrying fix to its file and requires the
// result to stay valid YAML: a suggested fix that breaks the workflow is
// worse than none.
func checkFixes(t *testing.T, in *Input, rep *Report) {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Fix == nil || len(f.Fix.Edits) == 0 {
			continue
		}
		src := string(in.Files[f.Fix.Edits[0].Path])
		fixed := applyEdits(src, append([]Edit{}, f.Fix.Edits...))
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(fixed), &n); err != nil {
			t.Errorf("%s %s: fix produces invalid YAML: %v\n%s", f.RuleID, f.Subject, err, fixed)
		}
	}
}
