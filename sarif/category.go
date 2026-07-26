package sarif

import (
	"strings"
)

// Category is the scan class a SARIF document belongs to. The values match the
// vocabulary vdb-api's SARIF persistence already speaks, so a Category can be
// handed straight to the persistence layer.
type Category string

const (
	CategorySAST       Category = "SAST"
	CategorySCA        Category = "SCA"
	CategoryIAC        Category = "IAC"
	CategorySecrets    Category = "SECRETS"
	CategoryOCI        Category = "OCI"
	CategoryLicense    Category = "LICENSE"
	CategoryLint       Category = "LINT"
	CategoryCompiler   Category = "COMPILER"
	CategoryPentest    Category = "PENTEST"
	CategoryDAST       Category = "DAST"
	CategoryCloud      Category = "CLOUD"
	CategoryCompliance Category = "COMPLIANCE"
	CategoryMalware    Category = "MALWARE"
)

// Route returns the /v2/cli.<route> path segment a third-party SARIF document
// of this category is submitted to. Empty for an unrecognised category.
func (c Category) Route() string {
	if _, ok := categoryRoutes[c]; !ok {
		return ""
	}
	return strings.ToLower(string(c)) + "-sarif"
}

// categoryRoutes is the closed set of categories the third-party SARIF route
// family accepts. Membership is what Route() and Valid() check.
var categoryRoutes = map[Category]struct{}{
	CategorySAST: {}, CategorySCA: {}, CategoryIAC: {}, CategorySecrets: {},
	CategoryOCI: {}, CategoryLicense: {}, CategoryLint: {}, CategoryCompiler: {},
	CategoryPentest: {}, CategoryDAST: {}, CategoryCloud: {},
	CategoryCompliance: {}, CategoryMalware: {},
}

// Valid reports whether c is a category the route family accepts.
func (c Category) Valid() bool {
	_, ok := categoryRoutes[c]
	return ok
}

// ParseCategory normalizes a user- or API-supplied category string.
func ParseCategory(s string) Category {
	c := Category(strings.ToUpper(strings.TrimSpace(s)))
	switch c {
	case "CONTAINER", "CONTAINERS":
		return CategoryOCI
	case "INFRA", "INFRASTRUCTURE":
		return CategoryIAC
	case "SECRET":
		return CategorySecrets
	case "QUALITY":
		return CategoryLint
	}
	if c.Valid() {
		return c
	}
	return ""
}

// driverCategories maps a normalized tool driver name to its scan category.
// Keys are produced by normalizeName: lowercased with every non-alphanumeric
// character removed, so "osv-scanner", "OSV Scanner" and "osvscanner" collide.
var driverCategories = map[string]Category{
	// SAST
	"gosec": CategorySAST, "semgrep": CategorySAST, "zizmor": CategorySAST,
	"bandit": CategorySAST, "brakeman": CategorySAST, "staticcheck": CategorySAST,
	"codeql": CategorySAST, "sonarqube": CategorySAST, "sonarcloud": CategorySAST,
	"pmd": CategorySAST, "spotbugs": CategorySAST, "findsecbugs": CategorySAST,
	"njsscan": CategorySAST, "mobsf": CategorySAST, "flawfinder": CategorySAST,
	"cppcheck": CategorySAST, "sonarlint": CategorySAST, "snykcode": CategorySAST,

	// SCA
	"grype": CategorySCA, "osvscanner": CategorySCA, "osv": CategorySCA,
	"dependencycheck": CategorySCA, "owaspdependencycheck": CategorySCA,
	"govulncheck": CategorySCA, "nancy": CategorySCA, "retirejs": CategorySCA,
	"snyk": CategorySCA, "snykopensource": CategorySCA, "cargoaudit": CategorySCA,
	"pipaudit": CategorySCA, "bundleraudit": CategorySCA, "npmaudit": CategorySCA,

	// IaC
	"checkov": CategoryIAC, "kics": CategoryIAC, "tfsec": CategoryIAC,
	"terrascan": CategoryIAC, "cfnlint": CategoryIAC, "cfnnag": CategoryIAC,
	"kubesec": CategoryIAC, "kubescore": CategoryIAC, "datree": CategoryIAC,
	"terraformcompliance": CategoryIAC, "kubelinter": CategoryIAC,
	"kubeaudit": CategoryIAC, "polaris": CategoryIAC, "defsec": CategoryIAC,

	// Secrets
	"gitleaks": CategorySecrets, "trufflehog": CategorySecrets,
	"detectsecrets": CategorySecrets, "ggshield": CategorySecrets,
	"gitguardian": CategorySecrets, "whispers": CategorySecrets,
	"talismanscan": CategorySecrets, "noseyparker": CategorySecrets,

	// Containers / OCI
	"dockle": CategoryOCI, "hadolint": CategoryOCI, "dockerscout": CategoryOCI,
	"clair": CategoryOCI, "anchoreengine": CategoryOCI, "conftest": CategoryOCI,

	// License
	"licensee": CategoryLicense, "licensefinder": CategoryLicense,
	"scancode": CategoryLicense, "licensechecker": CategoryLicense,

	// Lint / quality
	"clippy": CategoryLint, "eslint": CategoryLint, "golangcilint": CategoryLint,
	"ruff": CategoryLint, "rubocop": CategoryLint, "shellcheck": CategoryLint,
	"actionlint": CategoryLint, "hlint": CategoryLint, "swiftlint": CategoryLint,
	"stylelint": CategoryLint, "vale": CategoryLint,

	// Compiler diagnostics
	"rustc": CategoryCompiler, "clangtidy": CategoryCompiler,
	"msvc": CategoryCompiler, "gcc": CategoryCompiler,

	// DAST / pentest
	"zap": CategoryDAST, "owaspzap": CategoryDAST, "nuclei": CategoryPentest,
	"burpsuite": CategoryDAST, "nikto": CategoryDAST, "arachni": CategoryDAST,

	// Cloud posture
	"wiz": CategoryCloud, "prowler": CategoryCloud, "scoutsuite": CategoryCloud,
	"cloudsploit": CategoryCloud, "steampipe": CategoryCloud,

	// Malware
	"malscan": CategoryMalware, "yara": CategoryMalware, "clamav": CategoryMalware,
}

// hintCategories maps GitHub artifact names (and file basenames) that already
// disambiguate a multi-mode tool. This is the only reliable way to separate
// Trivy's filesystem, config and image modes, all of which report the driver
// name "Trivy".
var hintCategories = map[string]Category{
	"trivyfs": CategorySCA, "trivyfilesystem": CategorySCA, "trivyrepo": CategorySCA,
	"trivyconfig": CategoryIAC, "trivyiac": CategoryIAC, "trivymisconfig": CategoryIAC,
	"trivyimage": CategoryOCI, "trivycontainer": CategoryOCI,
	"trivylicense": CategoryLicense, "trivysecret": CategorySecrets,
	"grypeimage": CategoryOCI,
	"syftsbom":   CategorySCA,
}

// automationCategories maps a run.automationDetails.id token to a category.
// Trivy stamps its scan mode here, which is a stronger signal than any
// heuristic over rule ids.
var automationCategories = map[string]Category{
	"fs": CategorySCA, "filesystem": CategorySCA, "repo": CategorySCA,
	"rootfs": CategorySCA, "vuln": CategorySCA, "sbom": CategorySCA,
	"config": CategoryIAC, "misconfig": CategoryIAC, "misconfiguration": CategoryIAC,
	"iac": CategoryIAC, "defsec": CategoryIAC,
	"image": CategoryOCI, "container": CategoryOCI,
	"secret": CategorySecrets, "license": CategoryLicense,
}

// normalizeName lowercases and strips every non-alphanumeric character, so all
// the spellings of a tool name collapse to one key.
func normalizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// InferCategory decides which scan category a run belongs to, and explains why.
//
// Precedence, strongest evidence first:
//
//  1. the scanned file paths, when the hint or automation stamp names a
//     misconfiguration *mode* rather than a target. "trivy config" over a
//     repository whose only misconfigurable file is a Containerfile is a
//     container scan, and filing it under IaC is wrong.
//  2. hint — the GitHub artifact name or file basename. Workflows already name
//     these "trivy-fs" and "trivy-image", which is the only place that
//     distinction is recorded.
//  3. run.automationDetails.id / run.properties["scan_type"] — Trivy's mode stamp.
//  4. the scanned file paths, for everything else.
//  5. rule-id prefixes — CKV/AVD-/KSV are IaC checks, DS- is Dockerfile
//     security, CVE-/GHSA-/RUSTSEC-/GO-/PYSEC- are package advisories.
//  6. the driver-name catalog.
//
// The second return value is a short token naming the winning evidence, e.g.
// "hint:trivy-config" or "driver-name:gosec", so a misclassification is
// diagnosable from a workflow log alone.
func InferCategory(run Run, hint string) (Category, string) {
	hintCat, hintWhy := categoryFromHint(hint)
	autoCat, autoWhy := categoryFromAutomation(run)

	// A misconfiguration-mode run says how the tool was invoked, not what it
	// scanned. Let the files decide, and fall back to the mode's own guess.
	if isMisconfigMode(hint) || isMisconfigMode(automationToken(run)) {
		if c, why := categoryFromLocations(run); c != "" {
			return c, why
		}
	}

	if hintCat != "" {
		return hintCat, hintWhy
	}
	if autoCat != "" {
		return autoCat, autoWhy
	}
	if c, why := categoryFromLocations(run); c != "" {
		return c, why
	}
	if c, why := categoryFromRuleIDs(run); c != "" {
		return c, why
	}
	driver := normalizeName(ToolOf(run).Name)
	if c, ok := driverCategories[driver]; ok {
		return c, "driver-name:" + driver
	}
	return "", ""
}

func categoryFromHint(hint string) (Category, string) {
	if hint == "" {
		return "", ""
	}
	// Try the whole hint, then progressively shorter prefixes of its
	// dash/underscore-separated parts, so "trivy-fs.sarif" and "trivy-fs" both
	// resolve while "trivy" alone does not falsely win.
	base := hint
	if i := strings.IndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	if c, ok := hintCategories[normalizeName(base)]; ok {
		return c, "hint:" + base
	}
	if c, ok := driverCategories[normalizeName(base)]; ok {
		return c, "hint:" + base
	}
	return "", ""
}

func categoryFromAutomation(run Run) (Category, string) {
	var tokens []string
	if run.AutomationDetails != nil {
		if run.AutomationDetails.ID != "" {
			tokens = append(tokens, strings.Split(run.AutomationDetails.ID, "/")...)
		}
	}
	for _, key := range []string{"scan_type", "scanType", "type", "kind"} {
		if v := propString(run.Properties, key); v != "" {
			tokens = append(tokens, v)
		}
	}
	for _, t := range tokens {
		n := normalizeName(t)
		if n == "" {
			continue
		}
		if c, ok := automationCategories[n]; ok {
			return c, "automation:" + t
		}
	}
	return "", ""
}

// ruleIDPrefixCategories maps a rule-id prefix to the category it implies.
var ruleIDPrefixCategories = []struct {
	prefix string
	cat    Category
}{
	{"CKV", CategoryIAC}, {"AVD-", CategoryIAC},
	// DS- is Trivy's Dockerfile-security namespace, not an IaC namespace.
	{"DS-", CategoryOCI}, {"DS0", CategoryOCI},
	{"KSV", CategoryIAC}, {"AC_", CategoryIAC}, {"AWS.", CategoryIAC},
	{"CVE-", CategorySCA}, {"GHSA-", CategorySCA}, {"RUSTSEC-", CategorySCA},
	{"GO-", CategorySCA}, {"PYSEC-", CategorySCA}, {"OSV-", CategorySCA},
	{"GMS-", CategorySCA}, {"DLA-", CategorySCA}, {"USN-", CategorySCA},
}

// categoryFromRuleIDs takes the majority verdict over the run's rule ids. A
// single stray CVE-prefixed rule in a SAST report must not flip the whole run.
func categoryFromRuleIDs(run Run) (Category, string) {
	counts := map[Category]int{}
	var winner string
	total := 0
	for _, res := range run.Results {
		id := res.RuleID
		if id == "" {
			continue
		}
		total++
		up := strings.ToUpper(id)
		for _, p := range ruleIDPrefixCategories {
			if strings.HasPrefix(up, p.prefix) {
				counts[p.cat]++
				if winner == "" {
					winner = p.prefix
				}
				break
			}
		}
	}
	if total == 0 {
		return "", ""
	}
	best, bestN := Category(""), 0
	for c, n := range counts {
		if n > bestN {
			best, bestN = c, n
		}
	}
	// Require an outright majority — anything less is not evidence.
	if best == "" || bestN*2 <= total {
		return "", ""
	}
	return best, "rule-id:" + winner
}

// misconfigModes are the hint and automation tokens that name a *scanning mode*
// rather than a target: "trivy config", "misconfig", "iac". They were treated
// as proof of IaC, which is wrong often enough to matter — `trivy config` over a
// repository whose only misconfigurable file is a Containerfile is a container
// scan, and was being filed under IaC.
//
// A run matching one of these defers to what it actually scanned.
var misconfigModes = map[string]struct{}{
	"trivyconfig": {}, "trivyiac": {}, "trivymisconfig": {},
	"config": {}, "misconfig": {}, "misconfiguration": {}, "iac": {},
	"defsec": {},
}

// pathCategory classifies one scanned file by what kind of thing it is.
//
// This is the most direct evidence available: a rule id or an artifact name
// describes how the tool was invoked, whereas the path describes what it
// found something in.
func pathCategory(uri string) Category {
	if uri == "" {
		return ""
	}
	p := strings.ToLower(uri)
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		p = p[i+1:]
	}
	switch {
	// Container image definitions. Note "docker-compose" is deliberately not
	// here: it describes a deployment, which is infrastructure.
	case p == "dockerfile" || p == "containerfile",
		strings.HasPrefix(p, "dockerfile."), strings.HasPrefix(p, "containerfile."),
		strings.HasSuffix(p, ".dockerfile"), strings.HasSuffix(p, ".containerfile"):
		return CategoryOCI

	// Infrastructure definitions.
	case strings.HasSuffix(p, ".tf"), strings.HasSuffix(p, ".tf.json"),
		strings.HasSuffix(p, ".tfvars"), strings.HasSuffix(p, ".hcl"),
		strings.HasPrefix(p, "docker-compose"), strings.HasPrefix(p, "compose."),
		strings.HasSuffix(p, ".bicep"), p == "serverless.yml", p == "serverless.yaml",
		strings.Contains(p, "cloudformation"), strings.HasSuffix(p, ".cfn.yaml"),
		strings.HasSuffix(p, ".cfn.yml"):
		return CategoryIAC

	// Dependency manifests and lockfiles.
	case p == "go.mod" || p == "go.sum" || p == "package.json" ||
		p == "package-lock.json" || p == "yarn.lock" || p == "pnpm-lock.yaml" ||
		p == "requirements.txt" || p == "poetry.lock" || p == "pipfile.lock" ||
		p == "cargo.toml" || p == "cargo.lock" || p == "gemfile" ||
		p == "gemfile.lock" || p == "pom.xml" || p == "composer.json" ||
		p == "composer.lock" || p == "build.gradle" || p == "build.gradle.kts" ||
		p == "packages.lock.json" || p == "pubspec.lock" || p == "mix.lock":
		return CategorySCA
	}
	return ""
}

// categoryFromLocations takes the majority verdict over the files a run's
// results point at.
func categoryFromLocations(run Run) (Category, string) {
	counts := map[Category]int{}
	examples := map[Category]string{}
	total := 0
	for _, res := range run.Results {
		if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation == nil {
			continue
		}
		al := res.Locations[0].PhysicalLocation.ArtifactLocation
		if al == nil || al.URI == "" {
			continue
		}
		total++
		if c := pathCategory(al.URI); c != "" {
			counts[c]++
			if _, seen := examples[c]; !seen {
				examples[c] = al.URI
			}
		}
	}
	if total == 0 {
		return "", ""
	}
	best, bestN := Category(""), 0
	for c, n := range counts {
		if n > bestN {
			best, bestN = c, n
		}
	}
	// An outright majority, same bar as the rule-id vote: a repository with one
	// Containerfile among fifty Terraform files is an IaC scan.
	if best == "" || bestN*2 <= total {
		return "", ""
	}
	return best, "path:" + examples[best]
}

// isMisconfigMode reports whether a hint or automation token names a
// misconfiguration scanning mode rather than a target.
func isMisconfigMode(token string) bool {
	if token == "" {
		return false
	}
	base := token
	if i := strings.IndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	_, ok := misconfigModes[normalizeName(base)]
	return ok
}

// automationToken returns the run's scan-mode stamp, if it carries one.
func automationToken(run Run) string {
	if run.AutomationDetails != nil && run.AutomationDetails.ID != "" {
		parts := strings.Split(run.AutomationDetails.ID, "/")
		return parts[len(parts)-1]
	}
	for _, key := range []string{"scan_type", "scanType", "type", "kind"} {
		if v := propString(run.Properties, key); v != "" {
			return v
		}
	}
	return ""
}
