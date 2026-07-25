package sarif

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The corpus under testdata/corpus is the real output of the third-party
// scanners run by .github/workflows/scanners.yml, captured from the GitHub
// Actions run whose publish step failed with HTTP 503 on every file. Host paths
// are redacted to /workspace. Asserting against real tool output is the whole
// point — synthetic SARIF would not have caught grype's array-valued "purls",
// Trivy's ROOTPATH indirection, or zizmor's zero-byte file.
const workspace = "/workspace/vdb-site"

func readCorpus(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "corpus", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestDecomposeCorpus(t *testing.T) {
	cases := []struct {
		file        string
		hint        string
		wantCat     Category
		wantWhy     string
		wantTool    string
		wantVersion string
		minFindings int
		wantSevs    map[string]int
	}{
		{
			file: "grype.sarif", hint: "grype",
			wantCat: CategorySCA, wantWhy: "hint:grype",
			wantTool: "grype", wantVersion: "0.110.0", minFindings: 11,
		},
		{
			file: "kics.sarif", hint: "kics",
			wantCat: CategoryIAC, wantWhy: "hint:kics",
			wantTool: "KICS", wantVersion: "v2.1.20", minFindings: 22,
		},
		{
			// Both Trivy files report driver name "Trivy". Only the artifact
			// name tells the filesystem scan from the config scan.
			file: "trivy-fs.sarif", hint: "trivy-fs",
			wantCat: CategorySCA, wantWhy: "hint:trivy-fs",
			wantTool: "Trivy", wantVersion: "0.70.0", minFindings: 10,
		},
		{
			file: "trivy-config.sarif", hint: "trivy-config",
			wantCat: CategoryIAC, wantWhy: "hint:trivy-config",
			wantTool: "Trivy", wantVersion: "0.70.0", minFindings: 2,
		},
		{
			file: "terrascan.sarif", hint: "terrascan",
			wantCat: CategoryIAC, wantWhy: "hint:terrascan",
			wantTool: "terrascan", wantVersion: "1.19.9", minFindings: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			raw := readCorpus(t, tc.file)
			log, rep := ValidateBytes(raw, 50000)
			if rep.HasErrors() {
				t.Fatalf("unexpected validation errors:\n%s", rep)
			}
			findings, sum := Decompose(log, DecomposeOptions{
				Hint: tc.hint, RootPath: workspace, MaxResults: 50000,
			})

			if sum.Category != tc.wantCat {
				t.Errorf("category = %q (%s), want %q", sum.Category, sum.CategoryWhy, tc.wantCat)
			}
			if sum.CategoryWhy != tc.wantWhy {
				t.Errorf("categoryWhy = %q, want %q", sum.CategoryWhy, tc.wantWhy)
			}
			if sum.Tool.Name != tc.wantTool {
				t.Errorf("tool = %q, want %q", sum.Tool.Name, tc.wantTool)
			}
			if sum.Tool.Version != tc.wantVersion {
				t.Errorf("toolVersion = %q, want %q", sum.Tool.Version, tc.wantVersion)
			}
			if len(findings) < tc.minFindings {
				t.Errorf("findings = %d, want >= %d", len(findings), tc.minFindings)
			}

			for i, f := range findings {
				if f.RuleID == "" {
					t.Errorf("finding %d has no ruleId", i)
				}
				if f.Severity == "" {
					t.Errorf("finding %d (%s) has no severity", i, f.RuleID)
				}
				if f.Fingerprint == "" {
					t.Errorf("finding %d (%s) has no fingerprint", i, f.RuleID)
				}
				if strings.HasPrefix(f.File, workspace) {
					t.Errorf("finding %d file %q was not relativised", i, f.File)
				}
			}
		})
	}
}

// The two failure modes `tool > out.sarif || true` produces. Before this
// package both reached the API and came back as an opaque 503; now they are
// named locally, in the job that produced them.
func TestValidateRejectsBrokenRedirects(t *testing.T) {
	t.Run("zero-byte", func(t *testing.T) {
		raw := readCorpus(t, "zizmor-empty.sarif")
		_, rep := ValidateBytes(raw, 50000)
		if !rep.HasErrors() {
			t.Fatal("a zero-byte file must be an error")
		}
		if !strings.Contains(rep.String(), "empty") {
			t.Errorf("diagnostic should name the emptiness:\n%s", rep)
		}
		if !strings.Contains(rep.String(), "--output") {
			t.Errorf("diagnostic should point at the fix:\n%s", rep)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		raw := readCorpus(t, "truncated.sarif")
		_, rep := ValidateBytes(raw, 50000)
		if !rep.HasErrors() {
			t.Fatal("a truncated file must be an error")
		}
		if !strings.Contains(rep.String(), "document starts:") {
			t.Errorf("diagnostic should quote the head of the file:\n%s", rep)
		}
	})
}

// grype records package identity in an array-valued "purls" rule property.
func TestGrypePurlExtraction(t *testing.T) {
	log, _ := ValidateBytes(readCorpus(t, "grype.sarif"), 0)
	findings, _ := Decompose(log, DecomposeOptions{Hint: "grype", RootPath: workspace})

	withPurl := 0
	for _, f := range findings {
		if strings.HasPrefix(f.PackagePurl, "pkg:") {
			withPurl++
		}
	}
	if withPurl == 0 {
		t.Fatalf("no purls extracted from %d grype findings", len(findings))
	}
}

// Trivy writes repo-relative URIs plus a ROOTPATH base pointing at the runner's
// absolute checkout. Expanding the base and failing to strip it again would
// replace a clean path with a machine-specific one.
func TestTrivyRootPathIndirection(t *testing.T) {
	log, _ := ValidateBytes(readCorpus(t, "trivy-fs.sarif"), 0)

	t.Run("with workspace", func(t *testing.T) {
		findings, _ := Decompose(log, DecomposeOptions{Hint: "trivy-fs", RootPath: workspace})
		for _, f := range findings {
			if strings.HasPrefix(f.File, "/") {
				t.Errorf("file %q should be repo-relative", f.File)
			}
		}
	})

	t.Run("without workspace", func(t *testing.T) {
		findings, _ := Decompose(log, DecomposeOptions{Hint: "trivy-fs"})
		for _, f := range findings {
			if strings.Contains(f.File, workspace) {
				t.Errorf("file %q leaked the runner path when no RootPath was given", f.File)
			}
		}
	})
}

// KICS links rules to CWEs through run.taxonomies, not through tags.
func TestKICSCWEFromTaxonomy(t *testing.T) {
	log, _ := ValidateBytes(readCorpus(t, "kics.sarif"), 0)
	findings, _ := Decompose(log, DecomposeOptions{Hint: "kics", RootPath: workspace})

	withCWE := 0
	for _, f := range findings {
		if len(f.CWEs) > 0 {
			withCWE++
			for _, c := range f.CWEs {
				if c <= 0 || c > 99999 {
					t.Errorf("implausible CWE %d on %s", c, f.RuleID)
				}
			}
		}
	}
	if withCWE == 0 {
		t.Fatalf("no CWEs resolved from the CWE taxonomy across %d findings", len(findings))
	}
}

// The synthesized fingerprint becomes SarifResults.guid, which is upserted
// ON CONFLICT. A non-deterministic value would duplicate every row on a re-run.
func TestFingerprintIsDeterministic(t *testing.T) {
	raw := readCorpus(t, "kics.sarif")
	first, _ := ValidateBytes(raw, 0)
	second, _ := ValidateBytes(raw, 0)

	a, _ := Decompose(first, DecomposeOptions{Hint: "kics", RootPath: workspace})
	b, _ := Decompose(second, DecomposeOptions{Hint: "kics", RootPath: workspace})

	if len(a) != len(b) {
		t.Fatalf("finding counts differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Fingerprint != b[i].Fingerprint {
			t.Fatalf("finding %d fingerprint is not stable: %q vs %q", i, a[i].Fingerprint, b[i].Fingerprint)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct{ score, want string }{
		{"9.8", SeverityCritical}, {"9.0", SeverityCritical},
		{"8.0", SeverityHigh}, {"7.0", SeverityHigh},
		{"5.5", SeverityMedium}, {"4.0", SeverityMedium},
		{"2.0", SeverityLow}, {"0.1", SeverityLow},
		{"0.0", SeverityInformational},
		{"high", SeverityHigh}, {"moderate", SeverityMedium},
	}
	for _, c := range cases {
		if got := severityFromSecuritySeverity(c.score); got != c.want {
			t.Errorf("securitySeverity %q = %q, want %q", c.score, got, c.want)
		}
	}

	// The two directions must stay inverses for the shared vocabulary.
	for _, level := range []string{"error", "warning", "note"} {
		if got := LevelFromSeverity(SeverityFromLevel(level)); got != level {
			t.Errorf("level %q round-tripped to %q", level, got)
		}
	}
}

// An absent ruleIndex must not resolve to rule 0. This is why Result.RuleIndex
// is a pointer.
func TestRuleIndexAbsentIsNotZero(t *testing.T) {
	zero := 0
	run := Run{
		Tool: Tool{Driver: ToolComponent{
			Name:  "t",
			Rules: []ReportingDescriptor{{ID: "RULE-0", Name: "zero"}},
		}},
	}

	absent := Result{RuleID: "UNLISTED"}
	if rule, _ := resolveRule(&run, &absent); rule != nil {
		t.Errorf("absent ruleIndex resolved to rule %q", rule.ID)
	}

	present := Result{RuleID: "RULE-0", RuleIndex: &zero}
	rule, ok := resolveRule(&run, &present)
	if !ok || rule == nil || rule.ID != "RULE-0" {
		t.Errorf("ruleIndex 0 did not resolve to RULE-0 (ok=%v)", ok)
	}

	past := 7
	outOfRange := Result{RuleID: "X", RuleIndex: &past}
	if rule, ok := resolveRule(&run, &outOfRange); ok || rule != nil {
		t.Errorf("out-of-range ruleIndex must report not-ok, got rule=%v ok=%v", rule, ok)
	}
}

func TestCategoryRoutes(t *testing.T) {
	if got := CategoryIAC.Route(); got != "iac-sarif" {
		t.Errorf("IAC route = %q", got)
	}
	if got := CategorySCA.Route(); got != "sca-sarif" {
		t.Errorf("SCA route = %q", got)
	}
	if got := Category("NOPE").Route(); got != "" {
		t.Errorf("unknown category must have no route, got %q", got)
	}
	if ParseCategory("containers") != CategoryOCI {
		t.Error("containers should normalize to OCI")
	}
	if ParseCategory("infra") != CategoryIAC {
		t.Error("infra should normalize to IAC")
	}
}

// Suppressed results are excluded by default and counted separately, so a
// tool's own ignore list does not inflate the finding count.
func TestSuppressionHandling(t *testing.T) {
	log := &Log{Version: "2.1.0", Runs: []Run{{
		Tool: Tool{Driver: ToolComponent{Name: "gosec"}},
		Results: []Result{
			{RuleID: "G101", Level: "error", Message: Message{Text: "kept"}},
			{RuleID: "G102", Level: "error", Message: Message{Text: "ignored"},
				Suppressions: []Suppression{{Kind: "inSource", State: "accepted", Justification: "reviewed"}}},
			{RuleID: "G103", Level: "error", Message: Message{Text: "rejected suppression counts as live"},
				Suppressions: []Suppression{{Kind: "external", State: "rejected"}}},
		},
	}}}

	findings, sum := Decompose(log, DecomposeOptions{})
	if len(findings) != 2 {
		t.Errorf("findings = %d, want 2 (G101 and G103)", len(findings))
	}
	if sum.Suppressed != 1 {
		t.Errorf("suppressed = %d, want 1", sum.Suppressed)
	}

	all, _ := Decompose(log, DecomposeOptions{IncludeSuppressed: true})
	if len(all) != 3 {
		t.Errorf("with IncludeSuppressed findings = %d, want 3", len(all))
	}
}
