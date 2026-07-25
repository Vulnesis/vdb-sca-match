package sarif

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// cwePattern matches the bare forms tools use in tags and property values:
// "CWE-79", "cwe_79", "cwe 79", "CWE79".
var cwePattern = regexp.MustCompile(`(?i)^cwe[-_ ]?(\d{1,5})$`)

// codeqlCWEPattern matches CodeQL's taxonomy tag form: "external/cwe/cwe-079".
var codeqlCWEPattern = regexp.MustCompile(`(?i)(?:^|/)cwe[-_]?(\d{1,5})$`)

// cweFromToken extracts a CWE number from a single token, or 0.
func cweFromToken(tok string) int {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0
	}
	if m := cwePattern.FindStringSubmatch(tok); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if m := codeqlCWEPattern.FindStringSubmatch(tok); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	// A bare number in a field explicitly named "cwe" is unambiguous.
	if n, err := strconv.Atoi(tok); err == nil && n > 0 && n < 100000 {
		return n
	}
	return 0
}

// stringsFromProp coerces a property bag value into a token list. Tools write
// tags and cwe as a string, a []string, or a []any of strings.
func stringsFromProp(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			switch s := e.(type) {
			case string:
				out = append(out, s)
			case json.Number:
				out = append(out, s.String())
			case float64:
				out = append(out, strconv.FormatFloat(s, 'f', -1, 64))
			}
		}
		return out
	case json.Number:
		return []string{t.String()}
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	default:
		return nil
	}
}

// cweSet accumulates unique CWE numbers.
type cweSet map[int]struct{}

func (s cweSet) add(n int) {
	if n > 0 {
		s[n] = struct{}{}
	}
}

func (s cweSet) addTokens(tokens []string) {
	for _, t := range tokens {
		s.add(cweFromToken(t))
	}
}

func (s cweSet) sorted() []int {
	if len(s) == 0 {
		return nil
	}
	out := make([]int, 0, len(s))
	for n := range s {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// collectCWEs unions every CWE source available for one result:
//
//  1. rule.properties["cwe"] — the Vulnetix writer's form
//  2. rule.properties["tags"] — bare "CWE-79" and CodeQL's "external/cwe/cwe-079"
//  3. result.taxa and rule.relationships targeting a CWE tool component
//  4. run.taxonomies named CWE, resolved by the index carried on the reference
func collectCWEs(run *Run, res *Result, rule *ReportingDescriptor) []int {
	set := cweSet{}

	if rule != nil {
		set.addTokens(stringsFromProp(rule.Properties["cwe"]))
		set.addTokens(stringsFromProp(rule.Properties["cwes"]))
		set.addTokens(stringsFromProp(rule.Properties["tags"]))
		for _, rel := range rule.Relationships {
			collectCWEFromRef(run, rel.Target, set)
		}
	}
	if res != nil {
		set.addTokens(stringsFromProp(res.Properties["cwe"]))
		set.addTokens(stringsFromProp(res.Properties["tags"]))
		for _, t := range res.Taxa {
			collectCWEFromRef(run, t, set)
		}
	}
	return set.sorted()
}

// collectCWEFromRef resolves a descriptor reference that may point at a CWE
// taxonomy, either directly by id or by index into run.taxonomies.
func collectCWEFromRef(run *Run, ref ReportingDescriptorReference, set cweSet) {
	if ref.ID != "" {
		if n := cweFromToken(ref.ID); n > 0 && isCWEComponent(run, ref.ToolComponent) {
			set.add(n)
			return
		}
		// An id like "79" is only a CWE if the component says so.
		if isCWEComponent(run, ref.ToolComponent) {
			set.add(cweFromToken(ref.ID))
		}
	}
	if ref.Index == nil || run == nil || ref.ToolComponent == nil {
		return
	}
	comp := resolveTaxonomy(run, ref.ToolComponent)
	if comp == nil || !strings.EqualFold(comp.Name, "CWE") {
		return
	}
	if i := *ref.Index; i >= 0 && i < len(comp.Taxa) {
		set.add(cweFromToken(comp.Taxa[i].ID))
	}
}

// isCWEComponent reports whether a tool-component reference names the CWE
// taxonomy. An absent reference is treated as CWE only when the id already
// carries the "CWE-" prefix, which cweFromToken has verified by then.
func isCWEComponent(run *Run, ref *ToolComponentReference) bool {
	if ref == nil {
		return true
	}
	if strings.EqualFold(ref.Name, "CWE") {
		return true
	}
	comp := resolveTaxonomy(run, ref)
	return comp != nil && strings.EqualFold(comp.Name, "CWE")
}

// resolveTaxonomy looks a tool-component reference up in run.taxonomies.
func resolveTaxonomy(run *Run, ref *ToolComponentReference) *ToolComponent {
	if run == nil || ref == nil {
		return nil
	}
	if ref.Index != nil {
		if i := *ref.Index; i >= 0 && i < len(run.Taxonomies) {
			return &run.Taxonomies[i]
		}
	}
	if ref.Name != "" {
		for i := range run.Taxonomies {
			if strings.EqualFold(run.Taxonomies[i].Name, ref.Name) {
				return &run.Taxonomies[i]
			}
		}
	}
	if ref.GUID != "" {
		for i := range run.Taxonomies {
			if strings.EqualFold(run.Taxonomies[i].GUID, ref.GUID) {
				return &run.Taxonomies[i]
			}
		}
	}
	return nil
}

// collectTags returns the rule's and result's tag tokens, deduplicated and
// order-stable, for storage alongside the finding.
func collectTags(res *Result, rule *ReportingDescriptor) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(tokens []string) {
		for _, t := range tokens {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if rule != nil {
		add(stringsFromProp(rule.Properties["tags"]))
	}
	if res != nil {
		add(stringsFromProp(res.Properties["tags"]))
	}
	return out
}
