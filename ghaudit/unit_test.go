package ghaudit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/sarif"
)

func TestParseUses(t *testing.T) {
	for raw, want := range map[string]Uses{
		"actions/checkout@v4":                   {Kind: UsesRemote, Owner: "actions", Repo: "checkout", Ref: "v4"},
		"github/codeql-action/init@v3":          {Kind: UsesRemote, Owner: "github", Repo: "codeql-action", Path: "init", Ref: "v3"},
		"org/repo/.github/workflows/x.yml@main": {Kind: UsesReusable, Owner: "org", Repo: "repo", Path: ".github/workflows/x.yml", Ref: "main"},
		"./.github/actions/local":               {Kind: UsesLocal, Path: "./.github/actions/local"},
		"docker://alpine:3@sha256:abc":          {Kind: UsesDocker, Image: "alpine:3@sha256:abc"},
		"nonsense":                              {Kind: UsesInvalid},
	} {
		got := ParseUses(raw)
		got.Raw = ""
		if got != want {
			t.Errorf("ParseUses(%q) = %+v, want %+v", raw, got, want)
		}
	}
	if !ParseUses("a/b@" + strings.Repeat("a", 40)).PinnedToSHA() {
		t.Error("40-hex ref should be a SHA pin")
	}
	if ParseUses("a/b@" + strings.Repeat("a", 39)).PinnedToSHA() {
		t.Error("short SHA is not a pin")
	}
}

func TestNearPopularOwner(t *testing.T) {
	for owner, want := range map[string]string{
		"actoins": "actions", "action": "actions", "actions": "", "githb": "github",
		"aws-action": "aws-actions", "my-org": "", "dockr": "docker",
	} {
		if got := NearPopularOwner(owner); got != want {
			t.Errorf("NearPopularOwner(%q) = %q, want %q", owner, got, want)
		}
	}
}

func TestPaths(t *testing.T) {
	for p, want := range map[string]bool{
		".github/workflows/ci.yml": true, ".github/workflows/ci.yaml": true,
		".github/workflows/sub/ci.yml": false, "ci.yml": false, "docs/.github/workflows/ci.yml": false,
	} {
		if IsWorkflowPath(p) != want {
			t.Errorf("IsWorkflowPath(%q) != %v", p, want)
		}
	}
	for p, want := range map[string]bool{".github/CODEOWNERS": true, "action.yml": true, "src/main.go": false} {
		if IsRelevantPath(p) != want {
			t.Errorf("IsRelevantPath(%q) != %v", p, want)
		}
	}
}

func TestRulesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if !strings.HasPrefix(r.ID, "VNX-GH-") || r.Name == "" || r.Summary == "" || r.Description == "" || r.Remediation == "" || r.check == nil {
			t.Errorf("%s: incomplete metadata", r.ID)
		}
		if len(r.CWE) == 0 {
			t.Errorf("%s: no CWE", r.ID)
		}
		if r.CWSS == "" || !strings.HasPrefix(r.CWSS, "CWSS:1.0/") {
			t.Errorf("%s: bad CWSS vector %q", r.ID, r.CWSS)
		}
		if r.Severity.rank() == 0 {
			t.Errorf("%s: bad severity %q", r.ID, r.Severity)
		}
		if _, ok := ParseTask(string(r.Task)); !ok {
			t.Errorf("%s: bad task %q", r.ID, r.Task)
		}
		for _, g := range append(append([]string{}, r.Requires...), r.Enhances...) {
			if !knownFactGroup(g) {
				t.Errorf("%s: unknown fact group %q", r.ID, g)
			}
		}
	}
	if len(seen) < 50 {
		t.Errorf("expected the full catalogue, got %d rules", len(seen))
	}
}

func knownFactGroup(g string) bool {
	switch g {
	case FactRepo, FactActionsPolicy, FactBranches, FactEnvironments, FactActionRefs, FactCodeOwners,
		FactDeployKeys, FactWebhooks, FactCollaborators, FactOrg, FactRunnerGroups, FactSecurity:
		return true
	}
	return false
}

// TestCoverageWithoutFacts: an offline run reports settings rules as
// unknown rather than passing them, so a caller never marks a settings
// finding fixed just because it could not look.
func TestCoverageWithoutFacts(t *testing.T) {
	rep := Evaluate(&Input{Files: map[string][]byte{".github/workflows/a.yml": []byte("on: push\njobs: {}\n")}})
	states := map[string]string{}
	for _, c := range rep.Coverage {
		states[c.RuleID+"@"+c.Scope] = c.State
	}
	if states["VNX-GH-201@repo"] != "unknown" {
		t.Errorf("VNX-GH-201 should be unknown without facts, got %q", states["VNX-GH-201@repo"])
	}
	if states["VNX-GH-001@.github/workflows/a.yml"] != "evaluated" {
		t.Errorf("VNX-GH-001 should be evaluated on the file")
	}
	if states["VNX-GH-102@.github/workflows/a.yml"] != "unknown" {
		t.Errorf("VNX-GH-102 needs action refs and should be unknown")
	}
}

func TestTaskFilter(t *testing.T) {
	rep := Evaluate(&Input{Tasks: []Task{TaskOrg}})
	for _, r := range rep.Rules {
		if r.Task != TaskOrg {
			t.Fatalf("task filter leaked %s", r.ID)
		}
	}
}

// TestSARIFIsValidAndClassified renders a real fixture, validates it with
// the shared validator, and checks the decomposer files it as COMPLIANCE —
// the category the platform's snapshot ingest and the website route on.
func TestSARIFIsValidAndClassified(t *testing.T) {
	in := loadCase(t, "testdata/cases/workflow-misc")
	rep := Evaluate(in)
	l := rep.SARIF(SARIFOptions{ToolVersion: "1.0.0", RepositoryURI: "https://github.com/acme/app", Branch: "main", Revision: strings.Repeat("a", 40)})
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	parsed, vr := sarif.ValidateBytes(raw, 0)
	if vr.HasErrors() {
		t.Fatalf("SARIF invalid: %s", vr.String())
	}
	findings, sum := sarif.Decompose(parsed, sarif.DecomposeOptions{})
	if sum.Category != sarif.CategoryCompliance {
		t.Fatalf("category = %q (%s), want COMPLIANCE", sum.Category, sum.CategoryWhy)
	}
	if len(findings) != len(rep.Findings) {
		t.Fatalf("decomposed %d findings, report has %d", len(findings), len(rep.Findings))
	}
	byFP := map[string]*Finding{}
	for _, f := range rep.Findings {
		byFP[f.Fingerprint] = f
	}
	for _, d := range findings {
		f := byFP[d.Fingerprint]
		if f == nil {
			t.Fatalf("fingerprint %q lost in SARIF round trip", d.Fingerprint)
		}
		if d.Severity != string(f.Severity) {
			t.Errorf("%s: severity %q after round trip, want %q", f.RuleID, d.Severity, f.Severity)
		}
		if len(d.CWEs) == 0 {
			t.Errorf("%s: CWEs lost in round trip", f.RuleID)
		}
	}
	// CWSS travels on the rule descriptor, where the CLI's submit path reads it.
	for _, r := range parsed.Runs[0].Tool.Driver.Rules {
		if v, _ := r.Properties["cwss"].(string); !strings.HasPrefix(v, "CWSS:1.0/") {
			t.Errorf("%s: rule descriptor lost its CWSS vector", r.ID)
		}
	}
	if os.Getenv("GHAUDIT_DUMP_SARIF") != "" {
		_ = os.WriteFile(os.Getenv("GHAUDIT_DUMP_SARIF"), raw, 0o644)
	}
}

func TestFingerprintStableAcrossUnrelatedEdits(t *testing.T) {
	src := "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: greet\n        run: echo \"${{ github.event.pull_request.title }}\"\n"
	shifted := "# a comment\n\nname: renamed\n" + src
	fp := func(s string) string {
		rep := Evaluate(&Input{Repository: "acme/app", Files: map[string][]byte{".github/workflows/x.yml": []byte(s)}, RuleIDs: []string{"VNX-GH-001"}})
		if len(rep.Findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(rep.Findings))
		}
		return rep.Findings[0].Fingerprint
	}
	if fp(src) != fp(shifted) {
		t.Fatal("fingerprint changed when unrelated lines were added above the finding")
	}
}

func TestCatalogueDoc(t *testing.T) {
	const p = "../docs/ghaudit-rules.md"
	got := CatalogueMarkdown()
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, _ := os.ReadFile(p)
	if string(want) != got {
		t.Fatalf("%s is stale; run go test ./ghaudit -run TestCatalogueDoc -update", p)
	}
}
