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

	// The three classes the catalog lists that had no home here, so every tool
	// in them was either misfiled under the nearest survivor or dropped for
	// being unclassifiable. A mobile app scanner is not a source-code scanner,
	// a network scanner is not a web scanner, and a fuzzer's crash is neither.
	CategoryMobile  Category = "MOBILE"
	CategoryNetwork Category = "NETWORK"
	CategoryFuzzing Category = "FUZZING"
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
	CategoryMobile: {}, CategoryNetwork: {}, CategoryFuzzing: {},
}

// Valid reports whether c is a category the route family accepts.
func (c Category) Valid() bool {
	_, ok := categoryRoutes[c]
	return ok
}

// AllCategories returns every category the classifier can produce, in a stable
// order, so a server can assert it has a handler for each one instead of
// keeping its own copy of the list. Two hand-maintained lists is how a category
// gets added here, classified correctly, and then 404s on submission.
func AllCategories() []Category {
	return []Category{
		CategorySAST, CategorySCA, CategoryIAC, CategorySecrets, CategoryOCI,
		CategoryLicense, CategoryLint, CategoryCompiler, CategoryPentest,
		CategoryDAST, CategoryCloud, CategoryCompliance, CategoryMalware,
		CategoryMobile, CategoryNetwork, CategoryFuzzing,
	}
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
	case "MAST", "ANDROID", "IOS":
		return CategoryMobile
	case "HOST", "INFRASTRUCTURE-SCAN", "VULNSCAN":
		return CategoryNetwork
	case "FUZZ", "FUZZER":
		return CategoryFuzzing
	}
	if c.Valid() {
		return c
	}
	return ""
}

// driverCategories maps a normalized tool driver name to its scan category.
// Keys are produced by normalizeName: lowercased with every non-alphanumeric
// character removed, so "osv-scanner", "OSV Scanner" and "osvscanner" collide.
//
// The table covers the whole published integration catalog, not the handful of
// scanners our own workflows happen to run. A driver name absent from here
// falls through InferCategory to "", and `vulnetix gha upload` skips an
// unclassifiable report rather than filing it wrong — so a missing row is a
// tool that silently produces nothing, which is the failure mode this table
// exists to prevent. Where a tool self-reports under more than one spelling
// (its product name, its binary name, its vendor-prefixed name) every spelling
// gets a row; they cost nothing and guessing wrong costs a whole scan.
var driverCategories = map[string]Category{
	// ── SAST ────────────────────────────────────────────────────────────────
	"gosec": CategorySAST, "semgrep": CategorySAST, "semgreposs": CategorySAST,
	"opengrep": CategorySAST, "zizmor": CategorySAST,
	"bandit": CategorySAST, "brakeman": CategorySAST, "staticcheck": CategorySAST,
	"codeql": CategorySAST, "sonarqube": CategorySAST, "sonarcloud": CategorySAST,
	"sonarsource": CategorySAST, "sonarlint": CategorySAST,
	"pmd": CategorySAST, "spotbugs": CategorySAST, "findsecbugs": CategorySAST,
	"njsscan": CategorySAST, "nodejsscan": CategorySAST,
	"flawfinder": CategorySAST, "cppcheck": CategorySAST, "snykcode": CategorySAST,
	"checkmarx": CategorySAST, "checkmarxone": CategorySAST, "cxone": CategorySAST,
	"cxsast":  CategorySAST,
	"fortify": CategorySAST, "opentextfortify": CategorySAST, "fortifysca": CategorySAST,
	"microfocusfortify": CategorySAST,
	"coverity":          CategorySAST, "synopsyscoverity": CategorySAST,
	"veracode": CategorySAST, "veracodestaticanalysis": CategorySAST,
	"bearer": CategorySAST, "pumascan": CategorySAST, "pumascanpro": CategorySAST,
	"shiftleft": CategorySAST, "qwiet": CategorySAST, "qwietai": CategorySAST,
	"apiiro": CategorySAST, "cycode": CategorySAST, "arnica": CategorySAST,
	"mend": CategorySAST, "mendsast": CategorySAST, "whitesource": CategorySAST,
	"devskim": CategorySAST, "microsoftdevskim": CategorySAST,
	"securitycodescan": CategorySAST, "insider": CategorySAST,
	"aikido": CategorySAST, "aikidosecurity": CategorySAST,
	"contrast": CategorySAST, "contrastsecurity": CategorySAST,
	"infer": CategorySAST, "facebookinfer": CategorySAST,
	"detekt": CategorySAST, "psalm": CategorySAST, "phpstan": CategorySAST,
	"42crunch": CategorySAST, "42crunchrestapistaticsecuritytesting": CategorySAST,
	"msdo": CategorySAST, "microsoftsecuritydevops": CategorySAST,
	"salus": CategorySAST, "coinbasesalus": CategorySAST,

	// ── SCA ─────────────────────────────────────────────────────────────────
	"grype": CategorySCA, "osvscanner": CategorySCA, "osv": CategorySCA,
	"dependencycheck": CategorySCA, "owaspdependencycheck": CategorySCA,
	"govulncheck": CategorySCA, "nancy": CategorySCA, "retirejs": CategorySCA,
	"retire": CategorySCA,
	"snyk":   CategorySCA, "snykopensource": CategorySCA, "cargoaudit": CategorySCA,
	"pipaudit": CategorySCA, "bundleraudit": CategorySCA, "npmaudit": CategorySCA,
	"yarnaudit": CategorySCA, "pnpmaudit": CategorySCA, "composeraudit": CategorySCA,
	"blackduck": CategorySCA, "synopsys": CategorySCA, "blackduckscan": CategorySCA,
	"mendsca": CategorySCA, "endorlabs": CategorySCA, "endorctl": CategorySCA,
	"gemnasium": CategorySCA, "dependabot": CategorySCA,
	"syft": CategorySCA, "anchore": CategorySCA, "cdxgen": CategorySCA,
	"owaspcdxgen": CategorySCA, "tern": CategorySCA, "distro2sbom": CategorySCA,
	"sbomtool": CategorySCA, "microsoftsbomtool": CategorySCA,
	"spdxsbomgenerator": CategorySCA, "cyclonedxcli": CategorySCA,
	"cyclonedx": CategorySCA, "dockersbom": CategorySCA,
	"sonatype": CategorySCA, "nexusiq": CategorySCA, "sonatypenexusiq": CategorySCA,
	"jfrogxray": CategorySCA, "xray": CategorySCA, "jfrog": CategorySCA,
	"checkmarxsca": CategorySCA, "cxsca": CategorySCA, "checkmarxcxsca": CategorySCA,
	"debricked": CategorySCA, "opentextdebricked": CategorySCA,
	"parlay": CategorySCA, "socket": CategorySCA, "socketsecurity": CategorySCA,
	"phylum": CategorySCA, "renovate": CategorySCA,
	"dependencytrack": CategorySCA, "owaspdependencytrack": CategorySCA,
	"kubeclarity": CategorySCA, "apko": CategorySCA, "chainguardapko": CategorySCA,
	"deepfence": CategorySCA, "threatmapper": CategorySCA,

	// ── IaC ─────────────────────────────────────────────────────────────────
	"checkov": CategoryIAC, "kics": CategoryIAC, "tfsec": CategoryIAC,
	"terrascan": CategoryIAC, "cfnlint": CategoryIAC, "cfnnag": CategoryIAC,
	"kubesec": CategoryIAC, "kubescore": CategoryIAC, "datree": CategoryIAC,
	"terraformcompliance": CategoryIAC, "kubelinter": CategoryIAC,
	"kubeaudit": CategoryIAC, "polaris": CategoryIAC, "defsec": CategoryIAC,
	"snykiac": CategoryIAC, "snykinfrastructureascode": CategoryIAC,
	"templateanalyzer": CategoryIAC, "armttk": CategoryIAC,
	"pulumi": CategoryIAC, "crossguard": CategoryIAC, "pulumipolicy": CategoryIAC,
	"pike": CategoryIAC, "regula": CategoryIAC, "fugueregula": CategoryIAC,
	"kubescape": CategoryIAC, "tflint": CategoryIAC, "terraformdocs": CategoryIAC,
	// ghaudit's own driver: GitHub workflow, action and settings posture,
	// filed with the other misconfigurations.
	// Both brands' display names classify the same (parity with Vulnetix).
	"vulnetixgithub": CategoryIAC, "vulnesisgithub": CategoryIAC,

	// ── Secrets ─────────────────────────────────────────────────────────────
	"gitleaks": CategorySecrets, "trufflehog": CategorySecrets,
	"detectsecrets": CategorySecrets, "ggshield": CategorySecrets,
	"gitguardian": CategorySecrets, "whispers": CategorySecrets,
	"talismanscan": CategorySecrets, "talisman": CategorySecrets,
	"noseyparker": CategorySecrets, "betterleaks": CategorySecrets,
	"credscan": CategorySecrets, "semgrepsecrets": CategorySecrets,
	"githubsecretscanning": CategorySecrets, "secretscanning": CategorySecrets,

	// ── Containers / OCI ────────────────────────────────────────────────────
	"dockle": CategoryOCI, "hadolint": CategoryOCI, "dockerscout": CategoryOCI,
	"haskelldockerfilelinter": CategoryOCI,
	"clair":                   CategoryOCI, "anchoreengine": CategoryOCI,
	"snykcontainer": CategoryOCI, "qualysqscanner": CategoryOCI,
	"aquasecurity": CategoryOCI, "aqua": CategoryOCI,
	"sysdig": CategoryOCI, "sysdigsecure": CategoryOCI,
	"falco": CategoryOCI, "falcosecurity": CategoryOCI,

	// ── License ─────────────────────────────────────────────────────────────
	"licensee": CategoryLicense, "licensefinder": CategoryLicense,
	"scancode": CategoryLicense, "scancodetoolkit": CategoryLicense,
	"licensechecker": CategoryLicense,
	"fossa":          CategoryLicense, "fossology": CategoryLicense,
	"ort": CategoryLicense, "ossreviewtoolkit": CategoryLicense,
	"sw360": CategoryLicense, "clearlydefined": CategoryLicense,
	"reuse": CategoryLicense, "licensecheck": CategoryLicense,

	// ── Lint / quality ──────────────────────────────────────────────────────
	"clippy": CategoryLint, "eslint": CategoryLint, "golangcilint": CategoryLint,
	"ruff": CategoryLint, "rubocop": CategoryLint, "shellcheck": CategoryLint,
	"actionlint": CategoryLint, "hlint": CategoryLint, "swiftlint": CategoryLint,
	"stylelint": CategoryLint, "vale": CategoryLint,
	"pylint": CategoryLint, "biome": CategoryLint, "ktlint": CategoryLint,
	"androidlint": CategoryLint, "lint": CategoryLint, "lintr": CategoryLint,
	"codeclimate": CategoryLint, "trunk": CategoryLint, "trunkcheck": CategoryLint,
	"megalinter": CategoryLint, "spectral": CategoryLint, "stoplightspectral": CategoryLint,
	"mypy": CategoryLint, "flake8": CategoryLint, "markdownlint": CategoryLint,
	"yamllint": CategoryLint, "hadolintlint": CategoryLint,

	// ── Compiler diagnostics ────────────────────────────────────────────────
	"rustc": CategoryCompiler, "clangtidy": CategoryCompiler,
	"msvc": CategoryCompiler, "gcc": CategoryCompiler,
	"clang": CategoryCompiler, "llvm": CategoryCompiler, "llvmclang": CategoryCompiler,
	"cmake": CategoryCompiler, "roslyn": CategoryCompiler,
	"roslynanalyzers": CategoryCompiler, "binskim": CategoryCompiler,
	"microsoftrvisualcsharpcompiler": CategoryCompiler,

	// ── DAST ────────────────────────────────────────────────────────────────
	"zap": CategoryDAST, "owaspzap": CategoryDAST,
	"burpsuite": CategoryDAST, "burp": CategoryDAST,
	"nikto": CategoryDAST, "arachni": CategoryDAST, "wapiti": CategoryDAST,
	"w3af": CategoryDAST, "invicti": CategoryDAST, "netsparker": CategoryDAST,
	"acunetix": CategoryDAST, "brightsecurity": CategoryDAST, "neuralegion": CategoryDAST,
	"stackhawk": CategoryDAST, "hawkscan": CategoryDAST,
	"rapid7appspider": CategoryDAST, "appspider": CategoryDAST,
	"qualyswas": CategoryDAST, "aptori": CategoryDAST,

	// ── Pentest / disclosure ────────────────────────────────────────────────
	"nuclei":   CategoryPentest,
	"plextrac": CategoryPentest, "dradis": CategoryPentest, "faraday": CategoryPentest,
	"ghostwriter": CategoryPentest, "attackforge": CategoryPentest,
	"hackerone": CategoryPentest, "bugcrowd": CategoryPentest,
	"intigriti": CategoryPentest, "yeswehack": CategoryPentest,
	"synack": CategoryPentest, "cobalt": CategoryPentest,

	// ── Cloud posture ───────────────────────────────────────────────────────
	"wiz": CategoryCloud, "prowler": CategoryCloud, "scoutsuite": CategoryCloud,
	"cloudsploit": CategoryCloud, "steampipe": CategoryCloud,
	"cloudquery": CategoryCloud, "orca": CategoryCloud, "orcasecurity": CategoryCloud,
	"lacework": CategoryCloud, "prismacloud": CategoryCloud, "twistlock": CategoryCloud,
	"paloaltonetworks":          CategoryCloud,
	"microsoftdefenderforcloud": CategoryCloud, "defenderforcloud": CategoryCloud,
	"microsoftdefenderfordevops": CategoryCloud, "defenderfordevops": CategoryCloud,
	"crowdstrikefalcon": CategoryCloud, "crowdstrike": CategoryCloud,

	// ── Compliance / policy engines ─────────────────────────────────────────
	"opa": CategoryCompliance, "openpolicyagent": CategoryCompliance,
	"conftest": CategoryCompliance, "gatekeeper": CategoryCompliance,
	"kyverno": CategoryCompliance, "mitresaf": CategoryCompliance,
	"inspec": CategoryCompliance, "openscap": CategoryCompliance,

	// ── Mobile (MAST) ───────────────────────────────────────────────────────
	"mobsf": CategoryMobile, "mobsfscan": CategoryMobile,
	"nowsecure": CategoryMobile, "quixxi": CategoryMobile,
	"ostorlab": CategoryMobile, "appknox": CategoryMobile,

	// ── Network / host scanners ─────────────────────────────────────────────
	"nessus": CategoryNetwork, "tenable": CategoryNetwork,
	"openvas": CategoryNetwork, "greenbone": CategoryNetwork,
	"qualysvmdr": CategoryNetwork, "qualys": CategoryNetwork,
	"insightvm": CategoryNetwork, "rapid7insightvm": CategoryNetwork,
	"nexpose": CategoryNetwork, "nmap": CategoryNetwork,
	"crowdstrikespotlight": CategoryNetwork, "spotlight": CategoryNetwork,
	"pentesttools": CategoryNetwork, "pentesttoolscom": CategoryNetwork,
	"intruder": CategoryNetwork,
	"shodan":   CategoryNetwork,

	// ── Fuzzing ─────────────────────────────────────────────────────────────
	"afl": CategoryFuzzing, "aflplusplus": CategoryFuzzing,
	"libfuzzer": CategoryFuzzing, "ossfuzz": CategoryFuzzing,
	"honggfuzz": CategoryFuzzing, "jazzer": CategoryFuzzing,
	"clusterfuzz": CategoryFuzzing, "atheris": CategoryFuzzing,
	"boofuzz": CategoryFuzzing, "gofuzz": CategoryFuzzing,

	// ── Malware ─────────────────────────────────────────────────────────────
	"malscan": CategoryMalware, "yara": CategoryMalware, "clamav": CategoryMalware,
	"clamscan": CategoryMalware,
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
	"trivyk8s": CategoryIAC, "trivykubernetes": CategoryIAC, "trivysbom": CategorySCA,
	"grypeimage": CategoryOCI, "grypesbom": CategorySCA,
	"syftsbom": CategorySCA, "syftimage": CategoryOCI,

	// Snyk is one binary and four products; the workflow's job name is the only
	// place the product is written down.
	"snykcode": CategorySAST, "snykoss": CategorySCA, "snykopensource": CategorySCA,
	"snykcontainer": CategoryOCI, "snykiac": CategoryIAC,

	// Docker Scout emits both an SBOM and a CVE report under one driver name.
	"dockerscoutsbom": CategorySCA, "dockerscoutcves": CategoryOCI,

	// Semgrep's secrets product reports as plain "semgrep".
	"semgrepsecrets": CategorySecrets, "semgrepsupplychain": CategorySCA,

	// MobSF's two shapes: the static analyzer over source, and the app scanner.
	"mobsfscan": CategoryMobile, "mobsfapk": CategoryMobile,

	// Checkov over a Dockerfile is a container scan even though the tool is
	// sold as IaC; naming the job says which was meant.
	"checkovdockerfile": CategoryOCI, "checkovterraform": CategoryIAC,
	"checkovkubernetes": CategoryIAC,
}

// automationCategories maps a run.automationDetails.id token to a category.
// Trivy stamps its scan mode here, which is a stronger signal than any
// heuristic over rule ids.
var automationCategories = map[string]Category{
	"fs": CategorySCA, "filesystem": CategorySCA, "repo": CategorySCA,
	"rootfs": CategorySCA, "vuln": CategorySCA, "sbom": CategorySCA,
	"config": CategoryIAC, "misconfig": CategoryIAC, "misconfiguration": CategoryIAC,
	"iac": CategoryIAC, "defsec": CategoryIAC, "kubernetes": CategoryIAC, "k8s": CategoryIAC,
	"image": CategoryOCI, "container": CategoryOCI,
	"secret": CategorySecrets, "license": CategoryLicense,
	"dast": CategoryDAST, "webapp": CategoryDAST,
	"mobile": CategoryMobile, "android": CategoryMobile, "ios": CategoryMobile,
	"network": CategoryNetwork, "host": CategoryNetwork,
	"fuzz": CategoryFuzzing, "fuzzing": CategoryFuzzing,
	"compliance": CategoryCompliance, "policy": CategoryCompliance,
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
	for _, driver := range driverNameKeys(ToolOf(run).Name) {
		if c, ok := driverCategories[driver]; ok {
			return c, "driver-name:" + driver
		}
	}
	return "", ""
}

// driverNameKeys returns the lookup keys for a driver name: the name itself,
// then the name with a trailing version removed, then its leading word.
//
// Tools stamp their build into the driver name in ways no table can enumerate:
// "Semgrep OSS", "noseyparker-cli", "Opengrep OSS 1.27.1", and GitHub's SPDX
// export reports "protobom-v0.0.0-20260814182028-8c0ca4678565+dirty". Each of
// those normalizes to a string that matches nothing, so the run was
// unclassifiable on the driver name alone.
//
// The version cut requires a separator before the digit, which is what keeps
// 42Crunch, w3af and cfn-nag intact.
func driverNameKeys(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	keys := []string{normalizeName(name)}
	add := func(candidate string) {
		n := normalizeName(candidate)
		if n == "" {
			return
		}
		for _, seen := range keys {
			if seen == n {
				return
			}
		}
		keys = append(keys, n)
	}

	add(trimTrailingVersion(name))
	// The leading word, for the "<name> OSS" / "<name> Community" shapes.
	if i := strings.IndexAny(name, " \t-_"); i > 0 {
		add(name[:i])
	}

	return keys
}

// trimTrailingVersion cuts at the first separator that introduces a digit.
func trimTrailingVersion(name string) string {
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '-' && c != '_' && c != '@' && c != ' ' && c != '\t' {
			continue
		}
		rest := name[i+1:]
		if rest == "" {
			continue
		}
		if rest[0] >= '0' && rest[0] <= '9' {
			return name[:i]
		}
		if (rest[0] == 'v' || rest[0] == 'V') && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' {
			return name[:i]
		}
	}
	return name
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
		p == "package-lock.json" || p == "yarn.lock" || p == "pnpm-lock.yaml" || p == "bun.lock" ||
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
