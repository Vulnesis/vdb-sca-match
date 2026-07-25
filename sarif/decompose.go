package sarif

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// DecomposeOptions controls how a Log is flattened into Findings.
type DecomposeOptions struct {
	// CategoryOverride skips inference entirely. The server sets this from the
	// route so a client cannot file findings under a category it did not earn.
	CategoryOverride Category
	// DefaultCategory is used when inference finds no evidence at all.
	DefaultCategory Category
	// Hint is the GitHub artifact name or file basename; the strongest signal
	// for multi-mode tools such as Trivy.
	Hint string
	// RootPath relativises absolute file URIs (typically GITHUB_WORKSPACE).
	RootPath string
	// IncludeSuppressed keeps results the tool marked suppressed. They are
	// dropped by default and counted separately.
	IncludeSuppressed bool
	// MaxResults caps the number of findings produced. 0 means unlimited.
	MaxResults int
}

// Summary describes what a Decompose call saw.
type Summary struct {
	Tool        ToolInfo
	Category    Category
	CategoryWhy string
	Runs        int
	Rules       int
	Results     int
	Suppressed  int
	Truncated   bool
	BySeverity  map[string]int
	Diagnostics []Diagnostic
}

// String renders the one-line report the CLI logs per file.
func (s Summary) String() string {
	var b strings.Builder
	cat := string(s.Category)
	if cat == "" {
		cat = "UNKNOWN"
	}
	why := s.CategoryWhy
	if why == "" {
		why = "default"
	}
	fmt.Fprintf(&b, "%s (%s) tool=%s", cat, why, orUnknown(s.Tool.Name))
	if s.Tool.Version != "" {
		fmt.Fprintf(&b, " %s", s.Tool.Version)
	}
	fmt.Fprintf(&b, " results=%d", s.Results)
	if len(s.BySeverity) > 0 {
		fmt.Fprintf(&b, " (crit %d high %d med %d low %d info %d)",
			s.BySeverity[SeverityCritical], s.BySeverity[SeverityHigh],
			s.BySeverity[SeverityMedium], s.BySeverity[SeverityLow],
			s.BySeverity[SeverityInformational])
	}
	if s.Suppressed > 0 {
		fmt.Fprintf(&b, " suppressed=%d", s.Suppressed)
	}
	fmt.Fprintf(&b, " rules=%d", s.Rules)
	if s.Truncated {
		b.WriteString(" [truncated]")
	}
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Decompose flattens every run in a Log into normalized Findings and reports
// what it saw. It never returns an error: a malformed corner of the document
// produces a Diagnostic on the Summary and the rest is still decomposed.
// Validate is the function that decides whether a document is fit to submit.
func Decompose(l *Log, opt DecomposeOptions) ([]Finding, Summary) {
	sum := Summary{BySeverity: map[string]int{}}
	if l == nil {
		return nil, sum
	}
	sum.Runs = len(l.Runs)

	var findings []Finding
	for ri := range l.Runs {
		run := &l.Runs[ri]
		tool := ToolOf(*run)
		if sum.Tool.Name == "" {
			sum.Tool = tool
		}
		sum.Rules += countRules(run)

		if sum.Category == "" {
			switch {
			case opt.CategoryOverride != "":
				sum.Category, sum.CategoryWhy = opt.CategoryOverride, "override"
			default:
				if c, why := InferCategory(*run, opt.Hint); c != "" {
					sum.Category, sum.CategoryWhy = c, why
				}
			}
		}

		for i := range run.Results {
			res := &run.Results[i]

			if suppressed, kind, justification := suppressionOf(res); suppressed {
				sum.Suppressed++
				if !opt.IncludeSuppressed {
					continue
				}
				f := buildFinding(run, res, tool, opt, &sum, ri, i)
				f.Suppressed, f.SuppressionKind, f.SuppressionJustification = true, kind, justification
				findings = append(findings, f)
				sum.BySeverity[f.Severity]++
				continue
			}

			if opt.MaxResults > 0 && len(findings) >= opt.MaxResults {
				sum.Truncated = true
				break
			}
			f := buildFinding(run, res, tool, opt, &sum, ri, i)
			findings = append(findings, f)
			sum.BySeverity[f.Severity]++
		}
		if sum.Truncated {
			break
		}
	}

	if sum.Category == "" {
		sum.Category = opt.DefaultCategory
		if sum.Category != "" {
			sum.CategoryWhy = "default"
		}
	}
	sum.Results = len(findings)
	return findings, sum
}

// buildFinding normalizes one result.
func buildFinding(run *Run, res *Result, tool ToolInfo, opt DecomposeOptions, sum *Summary, runIdx, resIdx int) Finding {
	rule, ruleOK := resolveRule(run, res)
	if !ruleOK {
		sum.Diagnostics = append(sum.Diagnostics, Diagnostic{
			Severity: DiagWarning,
			Path:     fmt.Sprintf("/runs/%d/results/%d", runIdx, resIdx),
			Message:  "ruleIndex is out of range; rule metadata dropped",
			Hint:     "the tool wrote an index past the end of tool.driver.rules",
		})
	}

	uri, startLine, endLine, snippet, snipStart, snipEnd := locationOf(run, res, opt.RootPath)

	f := Finding{
		RuleID:      firstNonEmpty(res.RuleID, ruleID(rule)),
		Message:     strings.TrimSpace(res.Message.Text),
		Level:       res.Level,
		File:        uri,
		StartLine:   startLine,
		EndLine:     endLine,
		SARIFGuid:   res.GUID,
		CodeSnippet: snippet,

		SnippetStartLine: snipStart,
		SnippetEndLine:   snipEnd,

		ToolName:    tool.Name,
		ToolVersion: tool.Version,
		ToolVendor:  tool.Organization,
		CWEs:        collectCWEs(run, res, rule),
		Tags:        collectTags(res, rule),
	}

	if rule != nil {
		f.RuleName = firstNonEmpty(rule.Name, rule.ID)
		f.HelpURI = rule.HelpURI
		f.Description = messageText(rule.ShortDescription, rule.FullDescription)
	}
	if f.Level == "" && rule != nil && rule.DefaultConfiguration != nil {
		f.Level = rule.DefaultConfiguration.Level
	}

	f.SecuritySeverity, f.Severity = severityOf(res, rule)
	if f.Severity == "" {
		f.Severity = SeverityFromLevel(f.Level)
	}
	if f.Severity == "" {
		f.Severity = SeverityInformational
	}
	if f.Level == "" {
		f.Level = LevelFromSeverity(f.Severity)
	}

	f.PackagePurl = purlOf(res, rule)
	f.Fingerprint = fingerprintOf(res, tool.Name, uri)
	if f.SARIFGuid == "" {
		// SarifResults is keyed on this value with ON CONFLICT DO UPDATE. Most
		// tools emit no result guid at all, so without this fallback every
		// re-scan would mint a fresh random key and duplicate every row.
		f.SARIFGuid = f.Fingerprint
	}
	return f
}

// severityOf resolves a result's severity, returning the raw security-severity
// score alongside the normalized word.
//
// Order: the result's own security-severity, the rule's security-severity
// (where gosec, semgrep, trivy and grype all put it), the result's "severity"
// property (where the Vulnetix writer puts it), the rule's "severity" property,
// then the SARIF level.
func severityOf(res *Result, rule *ReportingDescriptor) (score, severity string) {
	if res != nil {
		if raw := propString(res.Properties, "security-severity"); raw != "" {
			if s := severityFromSecuritySeverity(raw); s != "" {
				return raw, s
			}
		}
	}
	if rule != nil {
		if raw := propString(rule.Properties, "security-severity"); raw != "" {
			if s := severityFromSecuritySeverity(raw); s != "" {
				return raw, s
			}
		}
	}
	if res != nil {
		if s := NormalizeSeverity(propString(res.Properties, "severity")); s != "" {
			return "", s
		}
	}
	if rule != nil {
		if s := NormalizeSeverity(propString(rule.Properties, "severity")); s != "" {
			return "", s
		}
	}
	if res != nil {
		if s := SeverityFromLevel(res.Level); s != "" {
			return "", s
		}
	}
	if rule != nil && rule.DefaultConfiguration != nil {
		if s := SeverityFromLevel(rule.DefaultConfiguration.Level); s != "" {
			return "", s
		}
	}
	return "", ""
}

// purlKeys are the property names SCA tools use to record a package URL.
// "purls" is grype's, and is an array.
var purlKeys = []string{"purl", "purls", "packagePurl", "package_url", "affected_package_purl"}

// purlOf looks for a package URL in the places SCA tools record one.
func purlOf(res *Result, rule *ReportingDescriptor) string {
	for _, key := range purlKeys {
		if res != nil {
			if v := firstPurl(res.Properties[key]); v != "" {
				return v
			}
		}
		if rule != nil {
			if v := firstPurl(rule.Properties[key]); v != "" {
				return v
			}
		}
	}
	return ""
}

// firstPurl accepts either a scalar or an array property value.
func firstPurl(v any) string {
	for _, s := range stringsFromProp(v) {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// suppressionOf reports whether the tool marked this result suppressed. A
// suppression whose state is explicitly "rejected" does not count.
func suppressionOf(res *Result) (bool, string, string) {
	for _, s := range res.Suppressions {
		if strings.EqualFold(strings.TrimSpace(s.State), "rejected") {
			continue
		}
		return true, s.Kind, s.Justification
	}
	return false, "", ""
}

// locationOf extracts the primary physical location. A missing or zero start
// line stays zero — never fabricated as line 1, which would put every
// location-less finding on the first line of a file it may not even name.
func locationOf(run *Run, res *Result, rootPath string) (uri string, startLine, endLine int, snippet string, snipStart, snipEnd int) {
	if len(res.Locations) == 0 {
		return "", 0, 0, "", 0, 0
	}
	pl := res.Locations[0].PhysicalLocation
	if pl == nil {
		return "", 0, 0, "", 0, 0
	}
	if pl.ArtifactLocation != nil {
		uri = resolveURI(run, pl.ArtifactLocation, rootPath)
	}
	if pl.Region != nil {
		startLine = pl.Region.StartLine
		endLine = pl.Region.EndLine
		if pl.Region.Snippet != nil {
			snippet = pl.Region.Snippet.Text
			snipStart, snipEnd = startLine, endLine
		}
	}
	if snippet == "" && pl.ContextRegion != nil && pl.ContextRegion.Snippet != nil {
		snippet = pl.ContextRegion.Snippet.Text
		snipStart, snipEnd = pl.ContextRegion.StartLine, pl.ContextRegion.EndLine
	}
	if endLine < startLine {
		endLine = 0
	}
	return uri, startLine, endLine, snippet, snipStart, snipEnd
}

// resolveURI turns a SARIF artifact location into a repo-relative path:
// percent-decoded, file:// stripped, uriBaseId expanded, and made relative to
// rootPath.
//
// uriBaseId expansion is only kept when the expanded path can then be made
// relative to rootPath. Trivy writes uri="api/go.mod" with a ROOTPATH base of
// the runner's absolute checkout directory; expanding that without being able
// to strip it again would turn a clean repo-relative path into a machine-
// specific one, which is strictly worse than what the tool wrote.
func resolveURI(run *Run, loc *ArtifactLocation, rootPath string) string {
	raw := decodePath(loc.URI)
	if raw == "" {
		return ""
	}

	if loc.URIBaseID != "" && run != nil {
		if base, ok := run.OriginalURIBaseIDs[loc.URIBaseID]; ok && base.URI != "" {
			b := decodePath(base.URI)
			if b != "" && !strings.HasPrefix(raw, b) {
				expanded := strings.TrimSuffix(b, "/") + "/" + strings.TrimPrefix(raw, "/")
				if rel, ok := relativeTo(rootPath, expanded); ok {
					return rel
				}
			}
		}
	}

	if rel, ok := relativeTo(rootPath, raw); ok {
		return rel
	}
	return trimRepoRootSlash(raw)
}

func decodePath(s string) string {
	if s == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	return strings.TrimPrefix(s, "file://")
}

// relativeTo reports the path relative to root, and whether it stayed inside.
func relativeTo(root, path string) (string, bool) {
	if root == "" || !filepath.IsAbs(path) {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return strings.TrimPrefix(rel, "./"), true
}

// fsRootDirs are the top-level directories that make a leading slash mean a
// real filesystem path rather than "relative to the repository root".
var fsRootDirs = map[string]struct{}{
	"home": {}, "usr": {}, "var": {}, "etc": {}, "opt": {}, "tmp": {},
	"root": {}, "mnt": {}, "srv": {}, "proc": {}, "sys": {}, "dev": {},
	"bin": {}, "sbin": {}, "lib": {}, "lib64": {}, "boot": {}, "run": {},
	"users": {}, "applications": {}, "library": {}, "private": {},
}

// trimRepoRootSlash drops the leading slash from paths like "/api/go.mod",
// which grype emits to mean "relative to the scan root". A path whose first
// segment is a real filesystem root directory is left alone — mangling
// /etc/passwd into etc/passwd would be a lie about where the finding is.
func trimRepoRootSlash(p string) string {
	p = strings.TrimPrefix(p, "./")
	if !strings.HasPrefix(p, "/") {
		return p
	}
	first := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
	if _, isFS := fsRootDirs[strings.ToLower(first)]; isFS {
		return p
	}
	return strings.TrimPrefix(p, "/")
}

func ruleID(r *ReportingDescriptor) string {
	if r == nil {
		return ""
	}
	return r.ID
}

func messageText(msgs ...*Message) string {
	for _, m := range msgs {
		if m != nil && strings.TrimSpace(m.Text) != "" {
			return strings.TrimSpace(m.Text)
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
