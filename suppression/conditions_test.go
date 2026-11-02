package suppression

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

type fakeConditions struct {
	calls int
	// holds maps an expression to the findings it is true for.
	holds map[string][]string
	fail  string
}

func (f *fakeConditions) Holds(_ context.Context, _ pgx.Tx, _ string, expr string, uuids []string) (map[string]bool, error) {
	f.calls++
	if expr == f.fail {
		return nil, errors.New("bad expression")
	}
	out := map[string]bool{}
	for _, u := range f.holds[expr] {
		out[u] = true
	}
	return out, nil
}

func pairFor(rule, expr, finding string) rulePair {
	return rulePair{r: ruleRow{Rule: vexrules.Rule{UUID: rule}, Expr: expr}, f: findingRow{UUID: finding}}
}

func pairKeys(ps []rulePair) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.r.Rule.UUID+"/"+p.f.UUID)
	}
	return out
}

// A rule with a when covers only the findings the evaluator says it holds for;
// rules without one are untouched, and each conditional rule costs one call.
func TestKeepHoldingFiltersConditionalRules(t *testing.T) {
	c := &fakeConditions{holds: map[string][]string{"kev": {"f1"}}}
	e := &Engine{Conditions: c}
	in := []rulePair{
		pairFor("plain", "", "f1"), pairFor("plain", "", "f2"),
		pairFor("cel", "kev", "f1"), pairFor("cel", "kev", "f2"),
	}
	got, err := e.keepHolding(context.Background(), nil, "org", in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"plain/f1", "plain/f2", "cel/f1"}
	if g := pairKeys(got); len(g) != len(want) || g[0] != want[0] || g[1] != want[1] || g[2] != want[2] {
		t.Fatalf("kept %v, want %v", g, want)
	}
	if c.calls != 1 {
		t.Fatalf("evaluator called %d times, want once per rule", c.calls)
	}
}

// With no evaluator, or one that fails, a conditional rule covers nothing:
// its anchors alone would suppress more than was declared.
func TestKeepHoldingFailsClosed(t *testing.T) {
	in := func() []rulePair {
		return []rulePair{pairFor("plain", "", "f1"), pairFor("cel", "kev", "f1"), pairFor("bad", "boom", "f1")}
	}
	got, err := (&Engine{}).keepHolding(context.Background(), nil, "org", in())
	if err != nil || len(got) != 1 || got[0].r.Rule.UUID != "plain" {
		t.Fatalf("no evaluator: kept %v err %v", pairKeys(got), err)
	}
	c := &fakeConditions{holds: map[string][]string{"kev": {"f1"}}, fail: "boom"}
	got, err = (&Engine{Conditions: c}).keepHolding(context.Background(), nil, "org", in())
	if err == nil {
		t.Fatal("evaluator error not reported")
	}
	if k := pairKeys(got); len(k) != 2 || k[0] != "plain/f1" || k[1] != "cel/f1" {
		t.Fatalf("failing rule kept or others dropped: %v", k)
	}
}
