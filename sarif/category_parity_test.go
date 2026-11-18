package sarif

import "testing"

// Vulnesis runs in parity with Vulnetix: a SARIF run from ghaudit classifies
// the same whichever brand's display name its driver carries.
func TestGHAuditDriverClassifiesUnderBothBrands(t *testing.T) {
	for _, name := range []string{"Vulnesis GitHub", "Vulnetix GitHub"} {
		var run Run
		run.Tool.Driver.Name = name
		if got, why := InferCategory(run, ""); got != CategoryIAC {
			t.Errorf("InferCategory(%q) = %q (%s), want IAC", name, got, why)
		}
	}
}
