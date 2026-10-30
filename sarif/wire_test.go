package sarif

import (
	"bytes"
	"reflect"
	"testing"
)

// ToMap and MapToLog are the two halves of the build-then-send wire format: the
// client maps a Log to the generic envelope shape, the server maps it back and
// re-parses. The DeepEqual catches a field that is dropped or reshaped on the
// way through; a renamed JSON tag is symmetric and survives a round trip, so the
// wire key names are pinned separately against the map.
func TestWireRoundTrip(t *testing.T) {
	ruleIndex := 0
	log := &Log{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{Driver: ToolComponent{
				Name:    "gosec",
				Version: "2.22.3",
				Rules: []ReportingDescriptor{
					{
						ID:               "G101",
						Name:             "Hardcoded credentials",
						ShortDescription: &Message{Text: "Potential hardcoded credentials"},
						Properties:       PropertyBag{"security-severity": "7.5"},
					},
					{
						ID:         "G104",
						Name:       "Errors not checked",
						Properties: PropertyBag{"security-severity": "3.2"},
					},
				},
			}},
			Results: []Result{
				{
					RuleID:    "G101",
					RuleIndex: &ruleIndex,
					Level:     "error",
					Message:   Message{Text: "potential hardcoded credentials"},
					Locations: []Location{{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: &ArtifactLocation{URI: "main.go"},
							Region:           &Region{StartLine: 10, StartColumn: 5},
						},
					}},
					Fingerprints:        map[string]string{"vulnetix/v1": "abc123"},
					PartialFingerprints: map[string]string{"primaryLocationLineHash/v1": "def456"},
					Properties:          PropertyBag{"security-severity": "7.5"},
				},
				{
					RuleID:  "G104",
					Level:   "warning",
					Message: Message{Text: "error return value not checked"},
					Locations: []Location{{
						PhysicalLocation: &PhysicalLocation{
							ArtifactLocation: &ArtifactLocation{URI: "util.go"},
							Region:           &Region{StartLine: 42},
						},
					}},
					Fingerprints: map[string]string{"vulnetix/v1": "ghi789"},
					Properties:   PropertyBag{"security-severity": "3.2"},
				},
			},
		}},
	}

	raw, err := Marshal(log)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	m, err := ToMap(log)
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}

	// Pin the key names the API envelope carries. A renamed tag would still
	// round-trip, so only an explicit check on the map catches it.
	for _, key := range []string{"$schema", "version", "runs"} {
		if _, ok := m[key]; !ok {
			t.Errorf("ToMap: top-level key %q missing", key)
		}
	}
	run := m["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	for _, key := range []string{"name", "version", "rules"} {
		if _, ok := driver[key]; !ok {
			t.Errorf("ToMap: tool.driver key %q missing", key)
		}
	}
	rule := driver["rules"].([]any)[0].(map[string]any)
	for _, key := range []string{"id", "name", "shortDescription", "properties"} {
		if _, ok := rule[key]; !ok {
			t.Errorf("ToMap: rule key %q missing", key)
		}
	}
	result := run["results"].([]any)[0].(map[string]any)
	for _, key := range []string{"ruleId", "ruleIndex", "level", "message", "locations", "fingerprints", "partialFingerprints", "properties"} {
		if _, ok := result[key]; !ok {
			t.Errorf("ToMap: result key %q missing", key)
		}
	}
	phys := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if uri := phys["artifactLocation"].(map[string]any)["uri"]; uri != "main.go" {
		t.Errorf("ToMap: physicalLocation.artifactLocation.uri = %v, want main.go", uri)
	}
	region := phys["region"].(map[string]any)
	if region["startLine"] != float64(10) || region["startColumn"] != float64(5) {
		t.Errorf("ToMap: region = %v, want startLine 10, startColumn 5", region)
	}
	// ruleIndex 0 must survive as an explicit 0, not be omitted (see
	// TestRuleIndexAbsentIsNotZero).
	if result["ruleIndex"] != float64(0) {
		t.Errorf("ToMap: ruleIndex = %v, want 0", result["ruleIndex"])
	}

	got, rawFromMap, err := MapToLog(m)
	if err != nil {
		t.Fatalf("MapToLog: %v", err)
	}
	if !reflect.DeepEqual(got, log) {
		t.Errorf("ToMap/MapToLog round trip changed the Log:\n got: %#v\nwant: %#v", got, log)
	}
	reparsed, err := Parse(rawFromMap)
	if err != nil {
		t.Fatalf("Parse(MapToLog bytes): %v", err)
	}
	if !reflect.DeepEqual(reparsed, log) {
		t.Errorf("MapToLog returned bytes that parse to a different Log:\n got: %#v\nwant: %#v", reparsed, log)
	}

	// The on-disk artefact form must parse back to the same Log, from bytes and
	// from a reader.
	fromBytes, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(fromBytes, log) {
		t.Errorf("Parse(Marshal(log)) changed the Log:\n got: %#v\nwant: %#v", fromBytes, log)
	}
	fromReader, err := ParseReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !reflect.DeepEqual(fromReader, log) {
		t.Errorf("ParseReader(Marshal(log)) changed the Log:\n got: %#v\nwant: %#v", fromReader, log)
	}
}
