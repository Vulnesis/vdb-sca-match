package sarif

import (
	"bytes"
	"reflect"
	"testing"
)

// ToMap and MapToLog are the two halves of the build-then-send wire format: the
// client maps a Log to the generic envelope shape, the server maps it back and
// re-parses. A renamed or omitted JSON tag, or a changed field shape, would
// change what crosses the wire on one side only, and this DeepEqual catches it.
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

	got, _, err := MapToLog(m)
	if err != nil {
		t.Fatalf("MapToLog: %v", err)
	}

	if !reflect.DeepEqual(got, log) {
		t.Errorf("ToMap/MapToLog round trip changed the Log:\n got: %#v\nwant: %#v", got, log)
	}

	fromReader, err := ParseReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	fromBytes, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(fromReader, fromBytes) {
		t.Errorf("ParseReader and Parse disagree:\n reader: %#v\n  bytes: %#v", fromReader, fromBytes)
	}
}
