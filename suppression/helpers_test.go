package suppression

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Vulnesis/vdb-cyclonedx/vexrules"
)

// Characterisation tests for the pure decision helpers. They need no
// database: the DB-backed tests in engine_db_test.go skip without
// SUPPRESSION_TEST_DATABASE_URL, so without these the matcher's core logic
// would never run in CI.

func TestFindingRowToMatch(t *testing.T) {
	cases := []struct {
		name string
		row  findingRow
		want vexrules.Finding
	}{
		{
			name: "empty aliases give a nil slice",
			row:  findingRow{UUID: "f1", FindingID: "CVE-2024-1", Category: "SCA", Purl: "pkg:npm/a@1.0.0", Repo: "o/r"},
			want: vexrules.Finding{UUID: "f1", Category: "SCA", RuleID: "CVE-2024-1", FindingID: "CVE-2024-1", Purl: "pkg:npm/a@1.0.0", Value: "pkg:npm/a@1.0.0", Repository: "o/r"},
		},
		{
			name: "whitespace-only aliases give a nil slice",
			row:  findingRow{FindingID: "CVE-2024-1", Aliases: "  "},
			want: vexrules.Finding{RuleID: "CVE-2024-1", FindingID: "CVE-2024-1"},
		},
		{
			name: "JSON alias array is parsed",
			row:  findingRow{FindingID: "CVE-2024-1", Aliases: `["GHSA-xxxx-yyyy-zzzz","OSV-1"]`, Purl: "pkg:npm/a@1.0.0", PackageName: "a"},
			want: vexrules.Finding{RuleID: "CVE-2024-1", FindingID: "CVE-2024-1", Aliases: []string{"GHSA-xxxx-yyyy-zzzz", "OSV-1"}, Purl: "pkg:npm/a@1.0.0", Value: "pkg:npm/a@1.0.0"},
		},
		{
			name: "malformed aliases are ignored",
			row:  findingRow{FindingID: "CVE-2024-1", Aliases: `not json`},
			want: vexrules.Finding{RuleID: "CVE-2024-1", FindingID: "CVE-2024-1"},
		},
		{
			name: "SAST row without purl carries the file path from packageName",
			row:  findingRow{FindingID: "go.lang.security.audit.sqli", Category: "SAST", PackageName: "internal/db/query.go"},
			want: vexrules.Finding{Category: "SAST", RuleID: "go.lang.security.audit.sqli", FindingID: "go.lang.security.audit.sqli", FilePath: "internal/db/query.go"},
		},
		{
			name: "packageName equal to the finding id is not a file path",
			row:  findingRow{FindingID: "secret-1", PackageName: "secret-1"},
			want: vexrules.Finding{RuleID: "secret-1", FindingID: "secret-1"},
		},
		{
			name: "row with a purl never sets the file path",
			row:  findingRow{FindingID: "CVE-2024-1", Purl: "pkg:golang/x@v1.0.0", PackageName: "x"},
			want: vexrules.Finding{RuleID: "CVE-2024-1", FindingID: "CVE-2024-1", Purl: "pkg:golang/x@v1.0.0", Value: "pkg:golang/x@v1.0.0"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.row.toMatch(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("toMatch() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	f := findingRow{UUID: "f1", FindingID: "CVE-2024-1", Category: "SCA", Purl: "pkg:npm/a@1.0.0"}
	cases := []struct {
		name string
		rule ruleRow
		want bool
	}{
		{
			name: "exact findingUuid binding matches even with no anchor",
			rule: ruleRow{FindingUuid: "f1"},
			want: true,
		},
		{
			name: "other findingUuid delegates to the shared matcher (match)",
			rule: ruleRow{FindingUuid: "f2", Rule: vexrules.Rule{FindingID: "cve-2024-1"}},
			want: true,
		},
		{
			name: "other findingUuid delegates to the shared matcher (no match)",
			rule: ruleRow{FindingUuid: "f2", Rule: vexrules.Rule{FindingID: "CVE-2024-2"}},
			want: false,
		},
		{
			name: "no binding and no anchor never matches",
			rule: ruleRow{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matches(c.rule, f); got != c.want {
				t.Errorf("matches() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTriageFor(t *testing.T) {
	cases := []struct {
		typ, wantJust, wantResp string
	}{
		{"false_positive", "vulnerable_code_not_present", ""},
		{"nosec", "vulnerable_code_not_present", ""},
		{"mitigated", "protected_by_mitigating_control", ""},
		{"wont_fix", "", `["will_not_fix"]`},
		{"", "", `["will_not_fix"]`},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			just, resp := triageFor(c.typ)
			if just != c.wantJust || resp != c.wantResp {
				t.Errorf("triageFor(%q) = (%q, %q), want (%q, %q)", c.typ, just, resp, c.wantJust, c.wantResp)
			}
		})
	}
}

func TestActorOf(t *testing.T) {
	t.Run("empty primary falls back to the system actor", func(t *testing.T) {
		got := actorOf(vexrules.Identity{})
		if got.Kind != string(vexrules.EvidenceSystem) || got.ID != "vulnetix" || got.Label != "" || got.Email != "" || got.Verified {
			t.Errorf("actorOf(empty) = %+v, want system/vulnetix", got)
		}
		var back vexrules.Identity
		if err := json.Unmarshal([]byte(got.JSON), &back); err != nil {
			t.Fatalf("JSON does not unmarshal: %v", err)
		}
		if back.Primary.Kind != "" {
			t.Errorf("JSON marshals the input identity, got primary kind %q", back.Primary.Kind)
		}
	})
	t.Run("non-empty primary is preserved", func(t *testing.T) {
		id := vexrules.NewIdentity(vexrules.Evidence{
			Kind: vexrules.EvidenceConsolePrincipal, ID: "u-1", Label: "Ada", Email: "Ada@Example.com", Verified: true,
		})
		got := actorOf(id)
		want := actorColumns{Kind: "console_principal", ID: "u-1", Label: "Ada", Email: "ada@example.com", Verified: true}
		wantJSON, _ := json.Marshal(id)
		want.JSON = string(wantJSON)
		if got != want {
			t.Errorf("actorOf() = %+v, want %+v", got, want)
		}
	})
}

func TestTriageStateFor(t *testing.T) {
	cases := []struct {
		name                     string
		s                        vexrules.Statement
		state, justification, rp string
	}{
		{
			name:          "not_affected uses the statement justification",
			s:             vexrules.Statement{Status: vexrules.StatusNotAffected, Justification: "component_not_present", Raw: vexrules.RawDisposition{CDXJustification: "code_not_reachable"}},
			state:         "not_affected",
			justification: "component_not_present",
		},
		{
			name:          "not_affected falls back to the CDX justification",
			s:             vexrules.Statement{Status: vexrules.StatusNotAffected, Raw: vexrules.RawDisposition{CDXJustification: "code_not_reachable"}},
			state:         "not_affected",
			justification: "code_not_reachable",
		},
		{
			name:  "fixed is resolved",
			s:     vexrules.Statement{Status: vexrules.StatusFixed},
			state: "resolved",
		},
		{
			name:  "affected without responses is exploitable",
			s:     vexrules.Statement{Status: vexrules.StatusAffected},
			state: "exploitable",
		},
		{
			name:  "affected with CDX responses marshals them",
			s:     vexrules.Statement{Status: vexrules.StatusAffected, Raw: vexrules.RawDisposition{CDXResponses: []string{"update", "workaround_available"}}},
			state: "exploitable",
			rp:    `["update","workaround_available"]`,
		},
		{
			name: "under_investigation maps to nothing",
			s:    vexrules.Statement{Status: vexrules.StatusUnderInvestigation, Justification: "ignored"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, j, r := triageStateFor(c.s)
			if st != c.state || j != c.justification || r != c.rp {
				t.Errorf("triageStateFor() = (%q, %q, %q), want (%q, %q, %q)", st, j, r, c.state, c.justification, c.rp)
			}
		})
	}
}

func TestStatementKeys(t *testing.T) {
	s := vexrules.Statement{
		VulnID: "CVE-2024-1",
		Products: []vexrules.Product{
			{Purl: "pkg:npm/a@1.0.0"},
			{Purl: "pkg:npm/b@2.0.0", Subcomponents: []string{"pkg:npm/c@3.0.0", "pkg:npm/c@3.1.0"}},
		},
	}
	want := []string{vexrules.PurlBase("pkg:npm/a@1.0.0"), vexrules.PurlBase("pkg:npm/c@3.0.0")}
	if got := statementKeys(s, "o/r"); !reflect.DeepEqual(got, want) {
		t.Errorf("statementKeys() = %q, want %q", got, want)
	}
	// A statement with no product yields one vulnerability-only rule, whose
	// key is the empty purl base.
	if got := statementKeys(vexrules.Statement{VulnID: "CVE-2024-1"}, ""); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("statementKeys(no products) = %q, want [\"\"]", got)
	}
}

func TestSmallHelpers(t *testing.T) {
	t.Run("firstNonEmpty", func(t *testing.T) {
		if got := firstNonEmpty(); got != "" {
			t.Errorf("firstNonEmpty() = %q, want \"\"", got)
		}
		if got := firstNonEmpty("", ""); got != "" {
			t.Errorf("firstNonEmpty(\"\", \"\") = %q, want \"\"", got)
		}
		if got := firstNonEmpty("", "b", "c"); got != "b" {
			t.Errorf("firstNonEmpty(\"\", b, c) = %q, want b", got)
		}
	})
	t.Run("clip", func(t *testing.T) {
		cases := []struct {
			s    string
			n    int
			want string
		}{
			{"", 3, ""},
			{"abc", 3, "abc"},
			{"abcdef", 3, "abc"},
			{"abc", 0, ""},
		}
		for _, c := range cases {
			if got := clip(c.s, c.n); got != c.want {
				t.Errorf("clip(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
			}
		}
	})
	t.Run("nz", func(t *testing.T) {
		if got := nz(""); got != nil {
			t.Errorf("nz(\"\") = %v, want nil", got)
		}
		if got := nz("x"); got != "x" {
			t.Errorf("nz(x) = %v, want x", got)
		}
	})
	t.Run("groundedWord", func(t *testing.T) {
		if got := groundedWord(MintedVEX{Grounded: true, Repository: "o/r", GitCommit: "abc123"}); got != "grounded o/r@abc123" {
			t.Errorf("groundedWord(grounded) = %q", got)
		}
		if got := groundedWord(MintedVEX{Repository: "o/r", GitCommit: "abc123"}); got != "not tied to a commit" {
			t.Errorf("groundedWord(ungrounded) = %q", got)
		}
	})
	t.Run("ifGrounded", func(t *testing.T) {
		if got := ifGrounded(true, "v"); got != "v" {
			t.Errorf("ifGrounded(true, v) = %q, want v", got)
		}
		if got := ifGrounded(false, "v"); got != "" {
			t.Errorf("ifGrounded(false, v) = %q, want \"\"", got)
		}
	})
}
