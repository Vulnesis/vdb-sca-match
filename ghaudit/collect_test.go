package ghaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeGitHub answers Get from a path → (status, JSON) table. Unlisted paths
// are 404, which is what GitHub answers for anything it will not show.
type fakeGitHub map[string]struct {
	st   int
	body any
}

func (f fakeGitHub) Get(_ context.Context, p string, out any) (int, error) {
	r, ok := f[p]
	if !ok {
		return 404, fmt.Errorf("404 %s", p)
	}
	if out != nil && r.body != nil {
		b, _ := json.Marshal(r.body)
		if err := json.Unmarshal(b, out); err != nil {
			return 500, err
		}
	}
	if r.st >= 300 {
		return r.st, fmt.Errorf("%d", r.st)
	}
	return r.st, nil
}

func ok(body any) struct {
	st   int
	body any
} {
	return struct {
		st   int
		body any
	}{200, body}
}

func status(st int) struct {
	st   int
	body any
} {
	return struct {
		st   int
		body any
	}{st, nil}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

const (
	headSHA   = "1111111111111111111111111111111111111111"
	goodSHA   = "2222222222222222222222222222222222222222"
	forkSHA   = "3333333333333333333333333333333333333333"
	tagSHA    = "4444444444444444444444444444444444444444"
	commentSH = "5555555555555555555555555555555555555555"
)

func baseRepo() fakeGitHub {
	wf := "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: good/act@" + goodSHA + " # v1.0.0\n" +
		"      - uses: good/act@" + forkSHA + "\n" +
		"      - uses: tagged/act@v2\n"
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	return fakeGitHub{
		"/repos/acme/app": ok(map[string]any{"full_name": "acme/app", "visibility": "public", "default_branch": "main", "allow_forking": true,
			"security_and_analysis": map[string]any{"secret_scanning": map[string]any{"status": "enabled"}, "secret_scanning_push_protection": map[string]any{"status": "disabled"}}}),
		"/repos/acme/app/vulnerability-alerts":                             status(204),
		"/repos/acme/app/private-vulnerability-reporting":                  ok(map[string]any{"enabled": false}),
		"/repos/acme/app/actions/permissions":                              ok(map[string]any{"enabled": true, "allowed_actions": "all"}),
		"/repos/acme/app/actions/permissions/workflow":                     ok(map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true}),
		"/repos/acme/app/actions/permissions/fork-pr-contributor-approval": ok(map[string]any{"approval_policy": "first_time_contributors"}),
		"/repos/acme/app/rules/branches/main?per_page=100": ok([]any{
			map[string]any{"type": "pull_request", "ruleset_id": 9, "parameters": map[string]any{"required_approving_review_count": 1}},
			map[string]any{"type": "non_fast_forward", "ruleset_id": 9},
		}),
		"/repos/acme/app/rulesets/9":                                     ok(map[string]any{"bypass_actors": []any{map[string]any{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}}}),
		"/repos/acme/app/branches/main/protection":                       status(403),
		"/repos/acme/app/environments?per_page=100":                      ok(map[string]any{"environments": []any{map[string]any{"name": "prod"}}}),
		"/repos/acme/app/environments/prod/secrets?per_page=100":         ok(map[string]any{"secrets": []any{map[string]any{"name": "AWS"}}}),
		"/repos/acme/app/actions/secrets?per_page=100":                   ok(map[string]any{"secrets": []any{map[string]any{"name": "OLD", "updated_at": now.AddDate(-2, 0, 0).Format(time.RFC3339)}}}),
		"/repos/acme/app/keys?per_page=100":                              ok([]any{map[string]any{"id": 1, "title": "ci", "read_only": false, "created_at": now.AddDate(-1, 0, 0).Format(time.RFC3339)}}),
		"/repos/acme/app/hooks?per_page=100":                             ok([]any{map[string]any{"id": 2, "active": true, "config": map[string]any{"url": "https://hooks.example.com/t/SECRET-TOKEN", "insecure_ssl": "1"}}}),
		"/repos/acme/app/collaborators?affiliation=outside&per_page=100": ok([]any{}),
		"/repos/acme/app/commits/main":                                   ok(map[string]any{"sha": headSHA}),
		"/repos/acme/app/git/trees/" + headSHA + "?recursive=1": ok(map[string]any{"tree": []any{
			map[string]any{"path": ".github/workflows/x.yml", "type": "blob"},
			map[string]any{"path": "src/main.go", "type": "blob"},
		}}),
		"/repos/acme/app/contents/.github/workflows/x.yml?ref=" + headSHA: ok(map[string]any{"encoding": "base64", "content": b64(wf)}),
		// Action repositories.
		"/repos/good/act": ok(map[string]any{"full_name": "good/act", "default_branch": "main"}),
		"/repos/good/act/compare/main..." + goodSHA: ok(map[string]any{"status": "behind"}),
		"/repos/good/act/compare/main..." + forkSHA: ok(map[string]any{"status": "diverged"}),
		"/repos/good/act/tags?per_page=100":         ok([]any{map[string]any{"name": "v1.0.0", "commit": map[string]any{"sha": commentSH}}}),
		"/repos/good/act/branches?per_page=20":      ok([]any{map[string]any{"name": "main"}, map[string]any{"name": "v1"}}),
		"/repos/good/act/compare/v1..." + forkSHA:   ok(map[string]any{"status": "diverged"}),
		"/repos/good/act/commits/v1.0.0":            ok(map[string]any{"sha": commentSH}),
		"/repos/tagged/act":                         ok(map[string]any{"full_name": "new-owner/act", "default_branch": "main", "archived": true}),
		"/repos/tagged/act/git/ref/tags/v2":         ok(map[string]any{}),
		"/repos/tagged/act/commits/v2":              ok(map[string]any{"sha": tagSHA}),
	}
}

func TestCollectAndEvaluate(t *testing.T) {
	g := baseRepo()
	col, err := Collect(context.Background(), g, CollectOptions{Repo: "acme/app", Now: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	f := col.Facts
	b := f.Branches["main"]
	if b == nil || !b.Protected || b.RequiredApprovals != 1 || b.AllowForcePushes || !b.AllowDeletions || b.EnforceAdmins {
		t.Fatalf("branch facts wrong: %+v", b)
	}
	if got := f.Webhooks[0].URL; got != "hooks.example.com" {
		t.Fatalf("webhook URL must be host only, got %q", got)
	}
	if f.DeployKeys[0].IdleDays != -1 || f.DeployKeys[0].AgeDays < 360 {
		t.Fatalf("deploy key facts wrong: %+v", f.DeployKeys[0])
	}
	if a := f.Actions["good/act@"+goodSHA]; a == nil || a.ReachableFromRepo == nil || !*a.ReachableFromRepo || a.CommentSHA != commentSH {
		t.Fatalf("good pin facts wrong: %+v", a)
	}
	if a := f.Actions["good/act@"+forkSHA]; a == nil || a.ReachableFromRepo == nil || *a.ReachableFromRepo {
		t.Fatalf("fork-only SHA must be unreachable: %+v", a)
	}
	if a := f.Actions["tagged/act@v2"]; a == nil || a.RefType != "tag" || a.RedirectedTo != "new-owner/act" || !a.RepoArchived {
		t.Fatalf("tagged ref facts wrong: %+v", a)
	}
	if len(col.Files) != 1 || !f.Has(FactCodeOwners) || f.HasCodeOwners == nil || *f.HasCodeOwners {
		t.Fatalf("files/codeowners wrong: files=%d codeowners=%v", len(col.Files), f.HasCodeOwners)
	}

	rep := Evaluate(&Input{Repository: "acme/app", Files: col.Files, Facts: f})
	got := map[string]bool{}
	for _, fd := range rep.Findings {
		got[fd.RuleID] = true
	}
	for _, id := range []string{"VNX-GH-102", "VNX-GH-103", "VNX-GH-104", "VNX-GH-101", "VNX-GH-206", "VNX-GH-208", "VNX-GH-209", "VNX-GH-210", "VNX-GH-211", "VNX-GH-212", "VNX-GH-214", "VNX-GH-215", "VNX-GH-216", "VNX-GH-220", "VNX-GH-221", "VNX-GH-222"} {
		if !got[id] {
			t.Errorf("expected %s from collected facts", id)
		}
	}
	if got["VNX-GH-201"] {
		t.Errorf("ruleset protection must not read as unprotected")
	}
	// The ruleset blocks force pushes but has no deletion rule.
	for _, fd := range rep.Findings {
		if fd.RuleID == "VNX-GH-205" && (strings.Contains(fd.Message, "force") || !strings.Contains(fd.Message, "deletion")) {
			t.Errorf("VNX-GH-205 should report deletion only: %s", fd.Message)
		}
	}
}

// TestUnprotectedNeedsBothSources: when classic protection is unreadable and
// rulesets show nothing, the branch is unknown, never "unprotected".
func TestUnprotectedNeedsBothSources(t *testing.T) {
	g := baseRepo()
	g["/repos/acme/app/rules/branches/main?per_page=100"] = ok([]any{})
	col, _ := Collect(context.Background(), g, CollectOptions{Repo: "acme/app", MaxActionRefs: -1})
	if col.Facts.Has(FactBranches) {
		t.Fatalf("branches must not be collected when classic protection is unreadable and rulesets are empty")
	}
	rep := Evaluate(&Input{Repository: "acme/app", Files: col.Files, Facts: col.Facts, RuleIDs: []string{"VNX-GH-201"}})
	if len(rep.Findings) != 0 || rep.Coverage[0].State != "unknown" {
		t.Fatalf("VNX-GH-201 should be unknown, got %+v %+v", rep.Findings, rep.Coverage)
	}
	g["/repos/acme/app/branches/main/protection"] = status(404)
	col, _ = Collect(context.Background(), g, CollectOptions{Repo: "acme/app", MaxActionRefs: -1})
	rep = Evaluate(&Input{Repository: "acme/app", Files: col.Files, Facts: col.Facts, RuleIDs: []string{"VNX-GH-201"}})
	if len(rep.Findings) != 1 {
		t.Fatalf("with both sources read and nothing found, the branch is unprotected")
	}
}

func TestParseCodeOwners(t *testing.T) {
	rules := ParseCodeOwners("# owners\n* @acme/all\n/.github/ @acme/ci # ci\n\ndocs/ \n")
	if len(rules) != 3 || rules[1].Pattern != "/.github/" || strings.Join(rules[1].Owners, ",") != "@acme/ci" || len(rules[2].Owners) != 0 {
		t.Fatalf("parsed %+v", rules)
	}
	if !coversWorkflows(rules) {
		t.Fatal("/.github/ with owners covers workflows")
	}
}
