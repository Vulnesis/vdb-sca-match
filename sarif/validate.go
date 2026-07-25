package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Diagnostic severities.
const (
	DiagError   = "error"
	DiagWarning = "warning"
)

// Diagnostic is one problem found in a SARIF document, addressed by JSON
// pointer so an operator can find it in the file.
type Diagnostic struct {
	Severity string `json:"severity"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

func (d Diagnostic) String() string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(d.Severity))
	if d.Path != "" {
		fmt.Fprintf(&b, " %s", d.Path)
	}
	fmt.Fprintf(&b, ": %s", d.Message)
	if d.Hint != "" {
		fmt.Fprintf(&b, "\n    hint: %s", d.Hint)
	}
	return b.String()
}

// Report is the outcome of validating one document.
type Report struct {
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// HasErrors reports whether any diagnostic is fatal.
func (r Report) HasErrors() bool {
	for _, d := range r.Diagnostics {
		if d.Severity == DiagError {
			return true
		}
	}
	return false
}

// Errors returns only the fatal diagnostics.
func (r Report) Errors() []Diagnostic {
	var out []Diagnostic
	for _, d := range r.Diagnostics {
		if d.Severity == DiagError {
			out = append(out, d)
		}
	}
	return out
}

// String renders the report for a human reading a CI log.
func (r Report) String() string {
	if len(r.Diagnostics) == 0 {
		return ""
	}
	lines := make([]string, 0, len(r.Diagnostics))
	for _, d := range r.Diagnostics {
		lines = append(lines, d.String())
	}
	return strings.Join(lines, "\n")
}

func (r *Report) add(severity, path, message, hint string) {
	r.Diagnostics = append(r.Diagnostics, Diagnostic{
		Severity: severity, Path: path, Message: message, Hint: hint,
	})
}

// ValidateBytes parses and validates raw document bytes in one step. It is the
// entry point for callers holding a file: a parse failure has to become a
// Report too, since "this file is not JSON" is the single most common real
// failure and deserves the same treatment as a schema problem.
func ValidateBytes(raw []byte, maxResults int) (*Log, Report) {
	var rep Report

	if len(bytes.TrimSpace(raw)) == 0 {
		rep.add(DiagError, "", fmt.Sprintf("file is empty (%d bytes)", len(raw)),
			"the scanner likely wrote to stdout and a shell redirect captured nothing — use the tool's --output/--output-file flag instead of '> file.sarif'")
		return nil, rep
	}

	l, err := Parse(raw)
	if err != nil {
		rep.add(DiagError, "", fmt.Sprintf("not valid JSON: %v", err), jsonHint(raw))
		return nil, rep
	}

	rep = Validate(l, raw, maxResults)
	return l, rep
}

// jsonHint quotes the head of an unparseable document so the operator can see
// what actually landed in the file — usually a banner or a log line.
func jsonHint(raw []byte) string {
	head := bytes.TrimSpace(raw)
	const n = 120
	truncated := false
	if len(head) > n {
		head, truncated = head[:n], true
	}
	s := strings.ReplaceAll(string(head), "\n", "\\n")
	if truncated {
		s += "…"
	}
	return "document starts: " + s
}

// Validate checks a parsed document for the problems that make it unfit to
// ingest. It is intentionally the same function on both sides of the wire: the
// CLI runs it to produce a legible log before submitting, and the server runs
// it again because a client's verdict is not evidence.
//
// raw may be nil when the caller only has the parsed form.
func Validate(l *Log, raw []byte, maxResults int) Report {
	var rep Report
	if l == nil {
		rep.add(DiagError, "", "no document", "")
		return rep
	}

	if raw != nil && len(bytes.TrimSpace(raw)) == 0 {
		rep.add(DiagError, "", "file is empty (0 bytes)",
			"the scanner likely wrote to stdout and a shell redirect captured nothing")
		return rep
	}

	if strings.TrimSpace(l.Version) == "" {
		rep.add(DiagWarning, "/version", "no SARIF version declared",
			"expected \"2.1.0\"")
	} else if l.Version != "2.1.0" {
		rep.add(DiagWarning, "/version",
			fmt.Sprintf("SARIF version %q is not 2.1.0; parsing as 2.1.0 anyway", l.Version), "")
	}

	if len(l.Runs) == 0 {
		rep.add(DiagWarning, "/runs", "no runs — nothing to import", "")
		return rep
	}

	total := 0
	fingerprints := map[string][]string{}

	for ri := range l.Runs {
		run := &l.Runs[ri]
		runPath := fmt.Sprintf("/runs/%d", ri)

		// A warning, not an error: the caller may still be able to attribute the
		// report out of band. Whoever consumes the decomposition decides whether
		// an unattributable document is acceptable — on the third-party routes it
		// is not, and the handler rejects it there.
		if strings.TrimSpace(run.Tool.Driver.Name) == "" &&
			strings.TrimSpace(run.Tool.Driver.FullName) == "" {
			rep.add(DiagWarning, runPath+"/tool/driver/name",
				fmt.Sprintf("run %d declares no tool name", ri),
				"attribution must come from elsewhere, e.g. attribution.toolName")
		}

		for i := range run.Results {
			res := &run.Results[i]
			resPath := fmt.Sprintf("%s/results/%d", runPath, i)
			total++

			if res.RuleID == "" && res.RuleIndex == nil && res.Rule == nil {
				rep.add(DiagWarning, resPath,
					"result has neither ruleId nor ruleIndex; it will be imported without rule metadata", "")
			}
			if res.RuleIndex != nil {
				if i := *res.RuleIndex; i >= len(run.Tool.Driver.Rules) {
					rep.add(DiagWarning, resPath+"/ruleIndex",
						fmt.Sprintf("ruleIndex %d is past the end of tool.driver.rules (%d)", i, len(run.Tool.Driver.Rules)),
						"rule metadata will be dropped for this result")
				}
			}
			if len(res.Locations) == 0 {
				rep.add(DiagWarning, resPath+"/locations",
					"result has no locations; it will be imported without a file or line", "")
			}
			if fp := declaredFingerprint(res); fp != "" {
				fingerprints[fp] = append(fingerprints[fp], resPath)
			}
		}
	}

	if maxResults > 0 && total > maxResults {
		rep.add(DiagError, "/runs",
			fmt.Sprintf("%d results exceeds the %d-result cap", total, maxResults),
			"split the submission into chunks anchored on ingestionSnapshotUuid")
	}

	for fp, paths := range dedupedOverOne(fingerprints) {
		rep.add(DiagWarning, paths[0],
			fmt.Sprintf("fingerprint %s appears on %d results; later ones collapse into the first on ingest", short(fp), len(paths)),
			"")
	}

	return rep
}

// declaredFingerprint returns a fingerprint the tool actually wrote, ignoring
// anything this package would synthesize.
func declaredFingerprint(res *Result) string {
	if v := firstBySortedKey(res.Fingerprints); v != "" {
		return v
	}
	return firstBySortedKey(res.PartialFingerprints)
}

// dedupedOverOne returns only the entries with more than one occurrence, keyed
// deterministically so the report is stable across runs.
func dedupedOverOne(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if len(v) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// MapToLog converts the generic map form the API envelope carries back into a
// typed Log, so the server can re-parse exactly what the client sent without
// requiring the raw bytes to be transported separately.
func MapToLog(m map[string]any) (*Log, []byte, error) {
	if len(m) == 0 {
		return nil, nil, fmt.Errorf("empty document")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, nil, fmt.Errorf("re-marshal sarif: %w", err)
	}
	l, err := Parse(raw)
	if err != nil {
		return nil, raw, err
	}
	return l, raw, nil
}
