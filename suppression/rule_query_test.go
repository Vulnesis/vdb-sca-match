package suppression

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// The ApplyRule prefilter must select on one required anchor only. ORing the
// anchors put an unindexable LIKE beside the id lookup, so the planner read
// every Finding row the org had, and a product anchor pulled in every finding
// of that product whatever its vulnerability.

func TestRuleFindingQueryVulnerabilityRule(t *testing.T) {
	r := ruleRow{Rule: vexrules.Rule{
		VulnerabilityID:    "cve-2021-44228",
		ProductPurlBase:    "pkg:maven/org.apache.logging.log4j/log4j-core",
		RepositoryFullName: "Vulnetix/cli",
	}}
	q, args := ruleFindingQuery("org-1", r, 5000)

	for _, want := range []string{`lower("findingId") = ANY($3)`, `aliases IS NOT NULL AND lower(aliases) LIKE ANY($4)`} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
	for _, bad := range []string{"lower(purl)", `"packageName" LIKE`, " OR "} {
		if strings.Contains(q, bad) {
			t.Errorf("query has %q, which is not needed for a vulnerability rule:\n%s", bad, q)
		}
	}
	// Ids are folded to lower case for the lower() comparisons.
	want := []any{"org-1", 5000, []string{"cve-2021-44228"}, []string{`%"cve-2021-44228"%`}}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %#v, want %#v", args, want)
	}
}

func TestRuleFindingQueryDeduplicatesIDs(t *testing.T) {
	r := ruleRow{Rule: vexrules.Rule{RuleID: "CVE-2024-1", VulnerabilityID: "cve-2024-1"}}
	_, args := ruleFindingQuery("o", r, 10)
	if got := args[2].([]string); len(got) != 1 || got[0] != "cve-2024-1" {
		t.Errorf("ids = %v, want one cve-2024-1", got)
	}
}

func TestRuleFindingQueryBoundFindingAlwaysIncluded(t *testing.T) {
	r := ruleRow{FindingUuid: "f-1", Rule: vexrules.Rule{RuleID: "go.sql-injection"}}
	q, args := ruleFindingQuery("o", r, 10)
	if !strings.Contains(q, `uuid = $3`) || args[2] != "f-1" {
		t.Errorf("bound finding missing: %s %v", q, args)
	}
	if !strings.Contains(q, `lower("findingId") = ANY($4)`) {
		t.Errorf("rule id branch missing: %s", q)
	}
}

func TestRuleFindingQueryTargetValue(t *testing.T) {
	r := ruleRow{Rule: vexrules.Rule{TargetValue: "pkg:npm/lodash@4.17.20", ProductPurlBase: "pkg:npm/lodash"}}
	q, args := ruleFindingQuery("o", r, 10)
	if !strings.Contains(q, `lower(purl) = lower($3)`) || args[2] != "pkg:npm/lodash@4.17.20" {
		t.Errorf("target query = %s %v", q, args)
	}
	if strings.Contains(q, "LIKE") {
		t.Errorf("target value is an equality, not a pattern: %s", q)
	}
}

func TestRuleFindingQueryFilePath(t *testing.T) {
	r := ruleRow{Rule: vexrules.Rule{FilePath: `./internal\db_query.go`}}
	q, args := ruleFindingQuery("o", r, 10)
	if !strings.Contains(q, `"packageName" LIKE $3`) {
		t.Errorf("file query = %s", q)
	}
	if args[2] != `%internal/db\_query.go` {
		t.Errorf("file pattern = %q, want the underscore escaped", args[2])
	}
}

func TestRuleFindingQueryNoAnchorSelectsNothing(t *testing.T) {
	q, args := ruleFindingQuery("o", ruleRow{Rule: vexrules.Rule{ProductPurlBase: "pkg:npm/x"}}, 10)
	if !strings.Contains(q, "WHERE false") || len(args) != 2 {
		t.Errorf("a product with no anchor matches nothing (RuleMatches), got %s %v", q, args)
	}
}

func TestLikeEscape(t *testing.T) {
	if got := likeEscape(`a%b_c\d`); got != `a\%b\_c\\d` {
		t.Errorf("likeEscape = %q", got)
	}
}
