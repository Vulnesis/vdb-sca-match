package sarif

import "testing"

// The published integration catalog is the contract: every tool listed on
// /resolve/integrations is a tool a customer is told Vulnetix ingests. A driver
// name this package cannot classify is skipped by `vulnetix gha upload` with
// "could not classify", so the scan produces nothing and the card stays
// "available" forever — the exact failure this table prevents.
//
// The names below are what each tool writes into runs[].tool.driver.name, taken
// from the vendor's own SARIF output rather than from the catalog's display
// name, because those differ (hadolint calls itself "Haskell Dockerfile
// Linter", tfsec calls itself "defsec").
func TestCatalogToolsClassify(t *testing.T) {
	cases := []struct {
		driver string
		want   Category
	}{
		// SAST
		{"CodeQL", CategorySAST},
		{"Semgrep OSS", CategorySAST},
		{"opengrep", CategorySAST},
		{"SnykCode", CategorySAST},
		{"SonarQube", CategorySAST},
		{"Checkmarx One", CategorySAST},
		{"OpenText Fortify", CategorySAST},
		{"Coverity", CategorySAST},
		{"Veracode", CategorySAST},
		{"gosec", CategorySAST},
		{"Bearer", CategorySAST},
		{"Bandit", CategorySAST},
		{"Brakeman", CategorySAST},
		{"PMD", CategorySAST},
		{"Puma Scan", CategorySAST},
		{"ShiftLeft", CategorySAST},
		{"Apiiro", CategorySAST},
		{"Cycode", CategorySAST},
		{"zizmor", CategorySAST},
		{"Mend SAST", CategorySAST},
		{"DevSkim", CategorySAST},
		{"Flawfinder", CategorySAST},
		{"cppcheck", CategorySAST},
		{"Psalm", CategorySAST},
		{"PHPStan", CategorySAST},
		{"Security Code Scan", CategorySAST},
		{"nodejsscan", CategorySAST},
		{"Insider", CategorySAST},
		{"Aikido Security", CategorySAST},
		{"Contrast Security", CategorySAST},
		{"SpotBugs", CategorySAST},
		{"Facebook Infer", CategorySAST},
		{"detekt", CategorySAST},
		{"42Crunch", CategorySAST},
		{"Microsoft Security DevOps", CategorySAST},

		// SCA
		{"Snyk Open Source", CategorySCA},
		{"Black Duck", CategorySCA},
		{"Mend SCA", CategorySCA},
		{"Endor Labs", CategorySCA},
		{"Gemnasium", CategorySCA},
		{"OWASP Dependency-Check", CategorySCA},
		{"OSV Scanner", CategorySCA},
		{"Dependabot", CategorySCA},
		{"npm audit", CategorySCA},
		{"cdxgen", CategorySCA},
		{"Sonatype Nexus IQ", CategorySCA},
		{"grype", CategorySCA},
		{"syft", CategorySCA},
		{"JFrog Xray", CategorySCA},
		{"Checkmarx CxSCA", CategorySCA},
		{"Debricked", CategorySCA},
		{"Coinbase Salus", CategorySAST},
		{"Parlay", CategorySCA},
		{"Socket Security", CategorySCA},
		{"Phylum", CategorySCA},
		{"Renovate", CategorySCA},
		{"Retire.js", CategorySCA},
		{"Dependency-Track", CategorySCA},
		{"Arnica", CategorySAST},
		{"govulncheck", CategorySCA},
		{"Tern", CategorySCA},
		{"KubeClarity", CategorySCA},

		// IaC
		{"KICS", CategoryIAC},
		{"Checkov", CategoryIAC},
		{"Terrascan", CategoryIAC},
		{"defsec", CategoryIAC},
		{"Snyk IaC", CategoryIAC},
		{"TemplateAnalyzer", CategoryIAC},
		{"cfn-lint", CategoryIAC},
		{"cfn_nag", CategoryIAC},
		{"terraform-compliance", CategoryIAC},
		{"Pulumi", CategoryIAC},
		{"Pike", CategoryIAC},
		{"Regula", CategoryIAC},
		{"kubescape", CategoryIAC},

		// Secrets
		{"gitleaks", CategorySecrets},
		{"TruffleHog", CategorySecrets},
		{"GitGuardian", CategorySecrets},
		{"detect-secrets", CategorySecrets},
		{"Talisman", CategorySecrets},
		{"Whispers", CategorySecrets},
		{"CredScan", CategorySecrets},
		{"Betterleaks", CategorySecrets},

		// Containers
		{"Snyk Container", CategoryOCI},
		{"Qualys QScanner", CategoryOCI},
		{"Docker Scout", CategoryOCI},
		{"Clair", CategoryOCI},
		{"Dockle", CategoryOCI},
		{"Haskell Dockerfile Linter", CategoryOCI},
		{"Aqua Security", CategoryOCI},
		{"Sysdig Secure", CategoryOCI},
		{"Falco", CategoryOCI},

		// Cloud
		{"Wiz", CategoryCloud},
		{"Prisma Cloud", CategoryCloud},
		{"Orca Security", CategoryCloud},
		{"Lacework", CategoryCloud},
		{"Microsoft Defender for Cloud", CategoryCloud},
		{"Prowler", CategoryCloud},
		{"ScoutSuite", CategoryCloud},
		{"CloudSploit", CategoryCloud},
		{"Steampipe", CategoryCloud},
		{"CloudQuery", CategoryCloud},
		{"CrowdStrike Falcon", CategoryCloud},

		// Compliance
		{"Open Policy Agent", CategoryCompliance},
		{"Gatekeeper", CategoryCompliance},
		{"Kyverno", CategoryCompliance},
		{"Conftest", CategoryCompliance},
		{"MITRE SAF", CategoryCompliance},

		// License
		{"FOSSA", CategoryLicense},
		{"OSS Review Toolkit", CategoryLicense},
		{"ScanCode Toolkit", CategoryLicense},
		{"FOSSology", CategoryLicense},
		{"SW360", CategoryLicense},
		{"ClearlyDefined", CategoryLicense},
		{"LicenseFinder", CategoryLicense},

		// Lint / quality
		{"golangci-lint", CategoryLint},
		{"Pylint", CategoryLint},
		{"Ruff", CategoryLint},
		{"RuboCop", CategoryLint},
		{"Biome", CategoryLint},
		{"Stylelint", CategoryLint},
		{"SwiftLint", CategoryLint},
		{"ktlint", CategoryLint},
		{"Code Climate", CategoryLint},
		{"lintr", CategoryLint},
		{"MegaLinter", CategoryLint},
		{"spectral", CategoryLint},
		{"Trunk Check", CategoryLint},
		{"ShellCheck", CategoryLint},
		{"clippy", CategoryLint},

		// Compilers
		{"LLVM / Clang", CategoryCompiler},
		{"GCC", CategoryCompiler},
		{"CMake", CategoryCompiler},
		{"Roslyn", CategoryCompiler},
		{"BinSkim", CategoryCompiler},
		{"rustc", CategoryCompiler},
		{"MSVC", CategoryCompiler},

		// DAST
		{"OWASP ZAP", CategoryDAST},
		{"Burp Suite", CategoryDAST},
		{"Invicti", CategoryDAST},
		{"Acunetix", CategoryDAST},
		{"Nikto", CategoryDAST},
		{"Wapiti", CategoryDAST},
		{"Arachni", CategoryDAST},
		{"w3af", CategoryDAST},
		{"Bright Security", CategoryDAST},
		{"StackHawk", CategoryDAST},
		{"Rapid7 AppSpider", CategoryDAST},
		{"Qualys WAS", CategoryDAST},
		{"Aptori", CategoryDAST},

		// Mobile
		{"MobSF", CategoryMobile},
		{"mobsfscan", CategoryMobile},
		{"NowSecure", CategoryMobile},
		{"Quixxi", CategoryMobile},
		{"Ostorlab", CategoryMobile},
		{"Appknox", CategoryMobile},

		// Network
		{"Nessus", CategoryNetwork},
		{"OpenVAS", CategoryNetwork},
		{"Qualys VMDR", CategoryNetwork},
		{"Rapid7 InsightVM", CategoryNetwork},
		{"Nmap", CategoryNetwork},
		{"Nexpose", CategoryNetwork},
		{"CrowdStrike Spotlight", CategoryNetwork},
		{"Pentest-Tools.com", CategoryNetwork},
		{"Intruder", CategoryNetwork},
		{"Shodan", CategoryNetwork},

		// Fuzzing
		{"AFL++", CategoryFuzzing},
		{"libFuzzer", CategoryFuzzing},
		{"OSS-Fuzz", CategoryFuzzing},
		{"Honggfuzz", CategoryFuzzing},
		{"Jazzer", CategoryFuzzing},
		{"ClusterFuzz", CategoryFuzzing},
		{"Atheris", CategoryFuzzing},
		{"Boofuzz", CategoryFuzzing},

		// Pentest & disclosure
		{"Nuclei", CategoryPentest},
		{"PlexTrac", CategoryPentest},
		{"Dradis", CategoryPentest},
		{"Faraday", CategoryPentest},
		{"Ghostwriter", CategoryPentest},
		{"AttackForge", CategoryPentest},
		{"HackerOne", CategoryPentest},
		{"Bugcrowd", CategoryPentest},
		{"Intigriti", CategoryPentest},
		{"YesWeHack", CategoryPentest},
		{"Synack", CategoryPentest},
		{"Cobalt", CategoryPentest},

		// Malware
		{"ClamAV", CategoryMalware},
		{"YARA", CategoryMalware},
	}

	for _, tc := range cases {
		// No hint, no automation stamp, no results: the driver name is the only
		// evidence, which is the case this table is about.
		run := Run{}
		run.Tool.Driver.Name = tc.driver

		got, why := InferCategory(run, "")
		if got != tc.want {
			t.Errorf("%s: category = %q (%s), want %q", tc.driver, got, why, tc.want)
		}
	}
}

// Every category the classifier can return must have a route, or a correctly
// classified report is posted to /v2/cli.-sarif and 404s.
func TestEveryCategoryHasARoute(t *testing.T) {
	seen := map[Category]bool{}
	for _, c := range driverCategories {
		seen[c] = true
	}
	for _, c := range hintCategories {
		seen[c] = true
	}
	for _, c := range automationCategories {
		seen[c] = true
	}
	for c := range seen {
		if c.Route() == "" {
			t.Errorf("category %q is produced by the classifier but has no route", c)
		}
	}
}

// The multi-mode tools report one driver name across several products, so the
// workflow's artifact name is the only signal separating them. A hint that
// stopped resolving would silently re-file every one of those scans.
func TestMultiModeHints(t *testing.T) {
	cases := []struct {
		hint   string
		driver string
		want   Category
	}{
		{"snyk-code", "Snyk", CategorySAST},
		{"snyk-oss", "Snyk", CategorySCA},
		{"snyk-container", "Snyk", CategoryOCI},
		{"snyk-iac", "Snyk", CategoryIAC},
		{"trivy-image", "Trivy", CategoryOCI},
		{"trivy-fs", "Trivy", CategorySCA},
		{"trivy-k8s", "Trivy", CategoryIAC},
		{"grype-image", "grype", CategoryOCI},
		{"semgrep-secrets", "semgrep", CategorySecrets},
		{"docker-scout-sbom", "Docker Scout", CategorySCA},
		{"docker-scout-cves", "Docker Scout", CategoryOCI},
		{"mobsfscan", "mobsfscan", CategoryMobile},
	}

	for _, tc := range cases {
		run := Run{}
		run.Tool.Driver.Name = tc.driver

		got, why := InferCategory(run, tc.hint)
		if got != tc.want {
			t.Errorf("hint %q driver %q: category = %q (%s), want %q", tc.hint, tc.driver, got, why, tc.want)
		}
	}
}

// AllCategories must stay in step with the route table it exists to describe.
func TestAllCategoriesMatchesRouteTable(t *testing.T) {
	all := AllCategories()
	if len(all) != len(categoryRoutes) {
		t.Fatalf("AllCategories has %d entries, categoryRoutes has %d", len(all), len(categoryRoutes))
	}
	for _, c := range all {
		if !c.Valid() {
			t.Errorf("AllCategories lists %q, which has no route", c)
		}
	}
}
