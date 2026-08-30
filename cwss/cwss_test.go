package cwss

import (
	"math"
	"testing"
)

func mustParse(t *testing.T, v string) Metrics {
	t.Helper()
	m, err := Parse(v)
	if err != nil {
		t.Fatalf("Parse(%q): %v", v, err)
	}
	return m
}

func TestParseRejectsAnythingThatIsNotCWSS(t *testing.T) {
	// The ruleset shipped vectors like this for 1208 rules. Every one of the
	// metrics flagged here is a value CWSS 1.0.1 does not define, and parsing
	// them leniently scored every rule "low" regardless of its severity — which
	// is what this strictness exists to stop happening again silently.
	const bogus = "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H"

	if _, err := Parse(bogus); err == nil {
		t.Fatal("Parse accepted a vector with values CWSS does not define")
	}

	_, rejects := Lenient(bogus)
	want := map[string]bool{
		"AL:H": true, "IC:H": true, "FC:H": true, "RP:H": true, "RL:H": true,
		"AV:N": true, "AS:L": true, "IN:L": true, "SC:N": true,
		"CONF:N": true, "T:A": true,
	}
	if len(rejects) != len(want) {
		t.Fatalf("Lenient rejects = %v, want %d entries", rejects, len(want))
	}
	for _, r := range rejects {
		if !want[r] {
			t.Errorf("unexpected reject %q", r)
		}
	}
}

func TestParseAcceptsBothVectorForms(t *testing.T) {
	// Bare codes, and the redundant-weight form the browser calculator emits.
	bare := mustParse(t, "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:T/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W")
	weighted := mustParse(t, "TI:C,1.0/AP:A,1.0/AL:A,1.0/IC:N,1.0/FC:T,1.0/RP:N,1.0/RL:A,1.0/AV:I,1.0/AS:N,1.0/IN:A,1.0/SC:A,1.0/BI:C,1.0/DI:H,1.0/EX:H,1.0/EC:N,1.0/P:W,1.0")

	if bare.Vector() != weighted.Vector() {
		t.Fatalf("forms disagree:\n bare     %s\n weighted %s", bare.Vector(), weighted.Vector())
	}
	if got := bare.Score(); math.Abs(got-10.0) > 1e-9 {
		t.Errorf("all-maximum score = %v, want 10", got)
	}
}

func TestParseIgnoresAHandEditedWeight(t *testing.T) {
	// The weight in the `TI:L,9.9` form is redundant; the table decides. A
	// vector must not be able to smuggle in a score its metrics do not support.
	m := mustParse(t, "TI:L,9.9")
	if got := m.weight("TI"); got != 0.3 {
		t.Errorf("TI weight = %v, want 0.3 from the table", got)
	}
}

func TestVectorRoundTripsAndIsCanonical(t *testing.T) {
	const v = "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H"
	if got := mustParse(t, v).Vector(); got != v {
		t.Errorf("round trip:\n got  %s\n want %s", got, v)
	}

	// Unset metrics render explicitly as UK rather than being omitted, so a
	// stored vector never depends on the reader's defaults.
	partial := mustParse(t, "TI:C")
	const wantPartial = "CWSS:1.0/TI:C/AP:UK/AL:UK/IC:UK/FC:UK/RP:UK/RL:UK/AV:UK/AS:UK/IN:UK/SC:UK/BI:UK/DI:UK/EX:UK/EC:UK/P:UK"
	if partial.Vector() != wantPartial {
		t.Errorf("partial vector:\n got  %s\n want %s", partial.Vector(), wantPartial)
	}
}

func TestUnknownEverywhereScoresLowWhichIsWhyDeriveExists(t *testing.T) {
	// Documents the trap: an all-UK vector is not a neutral 5, it is 0.31.
	if got := Unknown().Score(); got < 0.30 || got > 0.32 {
		t.Fatalf("all-UK score = %v, want ~0.31", got)
	}
	if got := Unknown().Severity(); got != "low" {
		t.Errorf("all-UK severity = %q, want low", got)
	}
}

func TestZeroImpactIsInformationalNotUnknown(t *testing.T) {
	m := Derive(Input{Severity: "informational", Reach: ReachRemote})
	if got := m.Score(); got != 0 {
		t.Fatalf("informational score = %v, want 0", got)
	}
	if got := m.Severity(); got != "informational" {
		t.Errorf("severity = %q, want informational", got)
	}
}

// TestDeriveTable pins the whole severity x reach mapping. These numbers are the
// product decision, so a change to any weight or baseline metric has to come
// here and be argued for.
func TestDeriveTable(t *testing.T) {
	cases := []struct {
		severity string
		reach    Reach
		score    float64
		band     string
	}{
		{"critical", ReachRemote, 9.60, "critical"},
		{"high", ReachRemote, 8.60, "high"},
		{"medium", ReachRemote, 5.52, "medium"},
		{"low", ReachRemote, 3.03, "low"},
		{"informational", ReachRemote, 0.00, "informational"},

		// Local reach demotes by roughly one band, on purpose: the same weakness
		// behind an access requirement is genuinely less severe, and saying so is
		// the reason to score rather than relabel.
		{"critical", ReachLocal, 7.22, "high"},
		{"high", ReachLocal, 6.44, "medium"},
		{"medium", ReachLocal, 4.07, "medium"},
		{"low", ReachLocal, 2.19, "low"},
	}
	for _, c := range cases {
		m := Derive(Input{Severity: c.severity, Reach: c.reach})
		if got := m.Score(); math.Abs(got-c.score) > 0.01 {
			t.Errorf("%s/%s score = %.2f, want %.2f", c.severity, c.reach, got, c.score)
		}
		if got := m.Severity(); got != c.band {
			t.Errorf("%s/%s band = %q, want %q", c.severity, c.reach, got, c.band)
		}
		// Everything Derive emits must survive a strict re-parse unchanged.
		if _, err := Parse(m.Vector()); err != nil {
			t.Errorf("%s/%s vector does not re-parse: %v", c.severity, c.reach, err)
		}
	}
}

func TestDeriveIsAlwaysBetterThanNoVector(t *testing.T) {
	// Every band except informational must beat the all-UK score, otherwise
	// deriving would be no improvement on leaving the field null.
	floor := Unknown().Score()
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		for _, reach := range []Reach{ReachRemote, ReachLocal} {
			if got := Derive(Input{Severity: sev, Reach: reach}).Score(); got <= floor {
				t.Errorf("%s/%s scored %.2f, not above the all-UK floor %.2f", sev, reach, got, floor)
			}
		}
	}
}

func TestReachInference(t *testing.T) {
	cases := []struct {
		name string
		cwes []int
		tags []string
		want Reach
	}{
		{"injection CWE is remote", []int{89}, nil, ReachRemote},
		{"untrusted inclusion is remote", []int{829}, nil, ReachRemote},
		{"transport crypto failure is remote", []int{327}, nil, ReachRemote},
		{"a committed credential is remotely usable", []int{798}, nil, ReachRemote},
		{"tag rescues a missing CWE", nil, []string{"docker", "ssrf"}, ReachRemote},
		{"nothing known defaults local", nil, []string{"docker", "style"}, ReachLocal},
		{"unsafe permissions stay local", []int{732}, nil, ReachLocal},
		{"privilege escalation stays local", []int{250}, nil, ReachLocal},
		{"any remote CWE in the set wins", []int{732, 79}, nil, ReachRemote},
	}
	for _, c := range cases {
		if got := ReachFor(c.cwes, c.tags); got != c.want {
			t.Errorf("%s: ReachFor(%v, %v) = %q, want %q", c.name, c.cwes, c.tags, got, c.want)
		}
	}
}

func TestUnrecognisedSeverityIsTreatedAsMedium(t *testing.T) {
	got := Derive(Input{Severity: "spicy", Reach: ReachRemote}).Score()
	want := Derive(Input{Severity: "medium", Reach: ReachRemote}).Score()
	if got != want {
		t.Errorf("unrecognised severity scored %.2f, want medium's %.2f", got, want)
	}
}

func TestSetRejectsOffTableValues(t *testing.T) {
	m := Unknown()
	if err := m.Set("TI", "Z"); err == nil {
		t.Error("Set accepted a value outside TI's table")
	}
	if err := m.Set("NOPE", "H"); err == nil {
		t.Error("Set accepted a metric CWSS does not define")
	}
}
