package match

import (
	"strings"
	"testing"
)

// A withdrawal recorded by any source withdraws a non-CVE advisory, and a CVE is
// never hidden by a mirror's rejection.
func TestNotWithdrawnSQL(t *testing.T) {
	got := notWithdrawnSQL(`a."cveId"`)
	for _, want := range []string{
		`UPPER(a."cveId") LIKE 'CVE-%'`,
		`wd."cveId" = a."cveId"`,
		`IN ('REJECTED', 'WITHDRAWN')`,
		`NOT EXISTS`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("predicate missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "(")-strings.Count(got, ")") != 0 {
		t.Errorf("unbalanced parentheses:\n%s", got)
	}
}
