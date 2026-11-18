# PLAN — `vdb-sca-match`

The dependency→CVE matching engine. Given one resolved dependency, it returns every CVE that
affects it — by four methods — recording **which method matched**. It owns the multi-ecosystem
version comparator that does not exist anywhere in the Vulnesis codebase today (verified: no
semver/version library in `vdb-api` or `vdb-api-cyclonedx-uploads` go.mod; `/v2/cli.sca` relies on
pre-computed `PackageVersionCVE` rows).

## Why this module exists
- `vdb-sca-monitor`'s consumer re-evaluates each dependency against the **current** VDB and needs a
  real "version lower-than-fixed / within affected range" decision.
- The same engine is wired into `vdb-api-cyclonedx-uploads` (`LookupComponentCVEs`) and `vdb-api`
  `/v2/cli.sca` (`lookupVulnsForPurl`) so all three paths match identically.
- Consumed as a **sibling Go module** via `replace github.com/Vulnesis/vdb-sca-match =>
  ../vdb-sca-match`, cloned at container-build time (the `ietf-crit-spec` pattern).

## go.mod
Direct requirements (exact pins live in `go.mod`; this excerpt is kept to the direct ones):
```
module github.com/Vulnesis/vdb-sca-match
go 1.25.0
require (
    github.com/BurntSushi/toml v1.6.0                 // parse: uv.lock and pylock.toml
    github.com/Masterminds/semver/v3 v3.3.1           // semver-family ordering
    github.com/Vulnesis/vdb-cyclonedx v0.18.0         // suppression: shared vexrules matcher + VEX model
    github.com/aquasecurity/go-pep440-version v0.0.1  // PyPI / PEP 440
    github.com/google/uuid v1.6.0                     // suppression: application / VEX ids
    github.com/jackc/pgx/v5 v5.9.2
    github.com/masahiro331/go-mvn-version v0.0.0-20260119054159-d21fcd2e7de1 // Maven ordering
    gopkg.in/yaml.v3 v3.0.1                           // parse (pnpm-lock, workloads), ghaudit (workflows)
)
```

## File tree
```
vdb-sca-match/
├── go.mod
├── README.md
├── PLAN.md            // this file
├── querier.go        // Querier interface (pgxpool.Pool & pgx.Tx both satisfy)
├── dependency.go     // Dependency input struct
├── match.go          // Match struct + MatchDependency orchestrator
├── versionrange.go   // method "version-range:*" (CVEAffected + CVEAffectedVersion)
├── purl.go           // method "purl" (PackageVersionCVE registry-precise)
├── purlparse.go      // purl parsing for the purl method
├── cpe.go            // method "cpe" (CVEAffected.cpes / CVEMetadata.cpesJSON ILIKE)
├── crit.go           // method "crit" (CritRecord over already-matched cveIds)
├── distro.go         // OS-package matching (deb/rpm/apk): release, epoch, source package
├── ecosystem.go      // CanonicalEcosystem, EcosystemEvidence (registry URLs + vendors)
├── aliases.go        // alias-collated wildcard suppression across CVE/GHSA/OSV ids
├── branches.go       // branch-range reconciliation (finer backport ranges win)
├── withdrawn.go      // notWithdrawnSQL: drop withdrawn advisories
├── introduced.go     // drop zero-introduced rows superseded by a real lower bound
├── *_test.go         // match, versionrange, distro, ecosystem, withdrawn, pypi, release
├── version/
│   ├── compare.go          // Compare + Within: ecosystem-dispatched ordering + parse-ok signal
│   ├── ecosystems.go       // NormalizeEcosystem, SchemeFor, Classify, Order
│   ├── scheme.go           // Info (classification of one version)
│   ├── schemes_registry.go // ClassifyScheme, CompareScheme, SchemeIDs
│   ├── schemes.json        // the versioning-scheme catalogue (embedded)
│   ├── catalogue.go        // Catalogue, SchemeByID over schemes.json
│   ├── pick.go             // Safe Harbour: Pick / PickLatest / PickStable / PickRolling, Encode/DecodeRolling
│   ├── wildcard.go         // full- and segment-wildcard handling
│   ├── algo_*.go           // per-scheme algorithms (semver, ecosystems, distro, qualifier, recency)
│   ├── cmd/gen-schemes-doc/ // renders schemes.json to docs/version-schemes.md
│   ├── testdata/           // scheme and pick vectors
│   └── *_test.go
├── cwss/             // CWSS 1.0.1 scoring + derivation for rule findings with no CVE
├── parse/            // manifest / lockfile / workload parsers → ScopedPackage
├── sarif/            // shared SARIF 2.1.0 model: parse, validate, decompose to Findings
├── suppression/      // apply suppression rules, record applications, write Triage, mint VEX
├── ghaudit/          // GitHub posture engine (see below)
└── docs/             // ghaudit-rules.md, suppression-engine.md, version-schemes.md (generated)
```

## Querier abstraction (`querier.go`)
Lets every repo pass its `*pgxpool.Pool` (or a `pgx.Tx`) unchanged:
```go
package match
import (
    "context"
    "github.com/jackc/pgx/v5"
)
type Querier interface {
    Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
    QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
```

## Input + output (`dependency.go`, `match.go`)
```go
type Dependency struct {
    Key, Name, Version, Ecosystem, Purl, Cpe string
}

type Match struct {
    CveID, Source   string
    Method          string // "version-range:lessThan" | "version-range:lessThanOrEqual" |
                            // "version-range:exact" | "purl" | "cpe" | "crit"
    VulnerableRange string // the range expression that matched → Finding.vulnerableVersionRange
}

// MatchDependency runs version-range + purl + cpe, gathers matched cveIds, then runs crit over
// them. Every method fails soft (log + skip on its own error). Returns one Match per (cveId,
// method); a cveId reached by several methods yields several Match rows so the caller can fold the
// methods into Triage.analysisDetail.
func MatchDependency(ctx context.Context, q Querier, dep Dependency) ([]Match, error)
```

## Method 1 — version-range (`versionrange.go`)
Candidates from `CVEAffected` ⋈ `CVEAffectedVersion`, keyed by package name + ecosystem (mirrors
the `CVEAffected` fallback at `vdb-api/internal/handler/v2_cli_sca.go:399-404`):
```sql
-- $1 = dep.Name   $2 = dep.Ecosystem
SELECT ca."cveId", ca.source,
       cav.version, cav.status, cav."versionType", cav."lessThan", cav."lessThanOrEqual"
FROM "CVEAffected" ca
JOIN "CVEAffectedVersion" cav ON cav."affectedId" = ca.uuid
WHERE LOWER(COALESCE(ca."packageName", ca.product)) = LOWER($1)
  AND ($2 = '' OR ca."collectionURL" ILIKE '%' || LOWER($2) || '%' OR ca."collectionURL" IS NULL)
LIMIT 1000;
```
Decision per row via `version.Within`, scheme from `cav.versionType`:
- `status='affected'` AND `version == dep.Version` → `version-range:exact`.
- `lessThan != ''` AND `Compare(dep.Version, lessThan) < 0` → `version-range:lessThan` ("lower
  than fixed"); range string `">= "+version+", < "+lessThan` when a lower bound exists.
- `lessThanOrEqual != ''` AND `Compare(dep.Version, lessThanOrEqual) <= 0` →
  `version-range:lessThanOrEqual`.
- Prefer rows with `isValidVersion = true` when the column is present.
- `Compare` returns `ok=false` (unparseable) → **conservative**: match only on exact string
  equality with `status='affected'`; otherwise skip + log. (Precision over recall.)

### Current behaviour (`versionrange.go` and helpers)
The query above is the original sketch. The implementation now:
- **Ecosystem scoping** via `versionRangeEcoClauses` + `EcosystemEvidence` (`ecosystem.go`):
  empty ecosystem → name-only; known ecosystem → `collectionURL LIKE ANY(registry urls)` or
  vendor (up to its first `:`) `= ANY(vendors)`; unmapped non-empty ecosystem → legacy
  `collectionURL LIKE '%eco%'`. `Dependency.NativeOnly` and `Dependency.Release` narrow further
  (distro release clause). PyPI names are PEP 503-normalised; Go module names match the module
  or any package path under it.
- **Candidate cap** `versionRangeCVELimit = 2000` distinct CVEs, chosen most-recently-published
  first in an inner subquery; the outer query re-selects every row of the surviving CVEs so a
  product's version rows are never truncated.
- **Rejected / withdrawn** advisories are dropped: `CVEMetadata.state NOT IN ('REJECTED',
  'WITHDRAWN')` and `notWithdrawnSQL` (`withdrawn.go`).
- **`isValidVersion = false`** rows are skipped before any fact is recorded (defensive; the main
  importer always writes `true`).
- **Per-CVE verdict** (`evaluateCVE` / `evaluateProduct`): CVE 5.1 precedence exact > range >
  wildcard, per-product unaffected suppression, lower bounds, segment wildcards (`1.2.*`) and
  `changes[]`. Zero-introduced rows superseded by a real lower bound are dropped
  (`introduced.go`).
- **Alias-collated wildcard suppression** (`aliases.go`): CVE/GHSA/OSV ids for one
  vulnerability are grouped (union-find over aliases); in a group that has specific
  affected-version evidence anywhere, wildcard/coarse-only matches are deleted and coarse method
  tokens are stripped from the rest. A group with no specific evidence keeps its all-versions
  `*` match.
- **Branch-range reconciliation** (`branches.go`): when two aliases span the same envelope and
  one has finer (backport) ranges, the finer one decides.

## Method 2 — purl (`purl.go`)
Registry-precise, mirrors `lookupVulnsForPurl` primary path (`v2_cli_sca.go:370-378`):
```sql
-- $1=ecosystem $2=fullName $3=version  (from ParsePurl on dep.Purl)
SELECT pvc."cveId", COALESCE(cm.source,'mitre')
FROM "PackageVersionCVE" pvc
JOIN "PackageVersion" pv ON pv.uuid = pvc."packageVersionId"
LEFT JOIN "CVEMetadata" cm ON cm."cveId" = pvc."cveId"
WHERE LOWER(pv.ecosystem) = LOWER($1)
  AND LOWER(pv."packageName") = LOWER($2)
  AND ($3 = '' OR pv.version = $3)
  AND pvc."relationshipType" IN ('affects','vulnerable')
LIMIT 500;
```
Method `"purl"`; range from `pvc.versionRange` when present. (PURL parsing reuses
`vdb-cyclonedx.ParsePurl` or a local copy.)

## Method 3 — cpe (`cpe.go`)
Only when `dep.Cpe != ""`. Reduce the CPE 2.3 string to a `cpe:2.3:a:vendor:product%` prefix:
```sql
-- $1 = 'cpe:2.3:a:vendor:product%'
SELECT DISTINCT "cveId", source FROM "CVEAffected" WHERE cpes ILIKE $1
UNION
SELECT DISTINCT "cveId", source FROM "CVEMetadata" WHERE "cpesJSON" ILIKE $1
LIMIT 500;
```
Method `"cpe"` (coarse, no version math — lower confidence; surfaced in `analysisDetail` so it's
auditable).

## Method 4 — crit (`crit.go`)
`CritRecord` is keyed `(cveId, provider, service, resourceType)` with **no package/purl/cpe
column** (`saas/prisma/models/crit.prisma`) — so CRIT can only **tag** cveIds already matched by
the other methods, never discover from a dependency:
```sql
-- $1 = matchedCveIds (text[])
SELECT "cveId", provider, service, "resourceType", "vectorString"
FROM "CritRecord" WHERE "cveId" = ANY($1);
```
Method `"crit"`.

## Version comparison (`version/compare.go`) — the only genuinely new algorithm
```go
package version

// cmp ∈ {-1,0,1}; ok=false ⇒ unparseable under this scheme ⇒ caller falls back to exact match.
func Compare(ecosystem, versionType, a, b string) (cmp int, ok bool)

// Within encapsulates the range check used by versionrange.go.
func Within(ecosystem, versionType, version, lowerBound, lessThan, lessThanOrEqual string) (inRange bool, ok bool)
```
Scheme dispatch — prefer `versionType` (`CVEAffectedVersion.versionType`: `semver`/`pep440`/
`git`/…), fall back to `ecosystem`:
- **semver family** (npm, cargo, golang, nuget, composer, hex, pub, swift) →
  `github.com/Masterminds/semver/v3` (`NewVersion` tolerates `v` prefix + missing patch).
- **pypi** → `github.com/aquasecurity/go-pep440-version`.
- **maven** → `github.com/masahiro331/go-mvn-version`.
- **fallback** (deb/rpm/apk/gem/generic/unknown) → hand-rolled normaliser: split on `.`/`-`/`+`,
  numeric segments compared as ints, alpha lexically, numeric < alpha for pre-release ordering.

Supersedes the dropped `compareSemver`/`semverParts` from the old CycloneDX parser.

### Scheme catalogue and Safe Harbour API (`version/`)
Beyond `Compare`/`Within`, the package now exposes a scheme catalogue and the Safe Harbour
version-picking API. The catalogue is `version/schemes.json` (embedded); its documentation page
`docs/version-schemes.md` is generated from it by `go run ./version/cmd/gen-schemes-doc`.
```go
// Scheme lookup and classification
func SchemeFor(ecosystem string) string           // scheme id for an ecosystem, "generic" if unknown
func NormalizeEcosystem(ecosystem string) string
func Classify(ecosystem, v string) Info           // judge one version under its ecosystem's scheme
func Order(ecosystem, a, b string) (int, bool)    // ok=false when either is not a version of the scheme
func ClassifyScheme(scheme, v string) Info
func CompareScheme(scheme, a, b string) (int, bool)
func SchemeIDs() []string
func Catalogue() []Scheme                         // every scheme, by family then id
func SchemeByID(id string) (Scheme, bool)

// Safe Harbour: pick fix targets from a package's (malware-free) releases
func Pick(ecosystem, running string, candidates []Candidate) Picks
func PickLatest(ecosystem string, candidates []Candidate) string
func PickStable(ecosystem, running string, candidates []Candidate) string
func PickRolling(ecosystem string, candidates []Candidate) ([]string, string)
func PickRollingTarget(ecosystem, running string, rolling []string) string
func PickParity(ecosystem, running string, candidates []Candidate) string
func EncodeRolling(versions []string) (string, error)
func DecodeRolling(s string) ([]string, error)

// Wildcards (used by versionrange.go)
func IsFullWildcard(s string) bool
func IsSegmentWildcard(pattern string) bool
func MatchSegmentWildcard(installed, pattern string) (matched, isSegWild bool)
```

## GitHub posture engine (`ghaudit/`)
A pure posture engine (no network, no database) over GitHub Actions workflows, composite
actions, the actions and images a workflow runs, and repository / organisation settings.
Callers collect the input (the CLI from the REST API via `Collect` + a `Getter`; vdb-site from
its webhook mirror), call `Evaluate`, and render the `Report`. Running the same engine on both
sides keeps a CLI snapshot and an event-driven Software Factory finding identical.
- **Tasks** (one CLI subcommand each): `workflows`, `actions`, `settings`, `org`
  (`AllTasks`, `ParseTask`).
- **Rules** register themselves via `register(&Rule{...})` in `rules_*.go`; `Rules()` and
  `RuleByID` expose the catalogue. Each rule carries severity, confidence, CWE, ATT&CK and a
  CWSS vector (scored through `cwss/`); a `Finding` may carry a `Fix` (edits the Software
  Factory can apply as a PR).
  `docs/ghaudit-rules.md` is rendered by `CatalogueMarkdown()`.
- **Output**: `Report.SARIF(SARIFOptions)` emits SARIF with driver `Vulnesis GitHub`
  (`ToolName`), which `sarif.Decompose` files under category `IAC`.
- **Analysis helpers**: expression and context taint (`expr.go`, `taint.go`), `uses:`
  parsing and pin checks (`uses.go`), workflow model (`workflow.go`), collected facts
  (`facts.go`).

## Unit tests (`version/compare_test.go`) — green before any wiring
- npm `4.17.20 < 4.17.21`; cargo `1.0.0-alpha < 1.0.0`.
- pep440 `1.0.0.post1 > 1.0.0`; `1.0.0.dev1 < 1.0.0`.
- go `v1.6.3 < v1.7.0`.
- maven `1.0-SNAPSHOT < 1.0`.
- generic `1.2.10 > 1.2.9` (int segments, not lexical).
- unparseable `latest`, `*`, `^1.0` → `ok=false`.
- `Within`: lessThan/lessThanOrEqual/exact boundary cases incl. lower-bound gating.

## Wiring into existing repos (after `compare_test` is green)
- **`vdb-api-cyclonedx-uploads`** — `internal/db/vulnlookup.go:50` `LookupComponentCVEs`: build a
  `match.Dependency` and union `MatchDependency`'s cveIds with the existing registry result;
  downstream `EnrichCVE` (already ported, `vulnlookup.go:106`) unchanged.
- **`vdb-api`** — `internal/handler/v2_cli_sca.go:360` `lookupVulnsForPurl`: same augmentation.
  Its Containerfile already clones one sibling (ietf-crit-spec) — add a second clone.

## Risks specific to this module
1. **Version ordering correctness** (highest) — Maven and distro (deb/rpm/apk) ordering are hard;
   the conservative "unparseable → exact-match-only" policy favors precision. Filter
   `CVEAffectedVersion.isValidVersion = true` when available.
2. **CRIT** tags only — never discovers from a dependency.
3. **CPE** matching is coarse (vendor:product prefix, no version math) — lower confidence.

## Source references
- `vdb-api/internal/handler/v2_cli_sca.go` (`lookupVulnsForPurl`, the `CVEAffected`/`PackageVersionCVE`
  query shapes, `enrichCves` for downstream context).
- `saas/prisma/models/cve.prisma` (`CVEAffected`, `CVEAffectedVersion.versionType/lessThan/
  lessThanOrEqual/isValidVersion`), `crit.prisma` (`CritRecord`).

## Companion plans
- `vdb-cyclonedx/PLAN.md` — the CycloneDX parser module.
- `~/.claude/plans/create-a-new-repo-distributed-wolf.md` and `Vulnesis/PLAN.md` — the
  `vdb-sca-monitor` service that consumes both modules.
