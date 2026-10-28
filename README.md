# vdb-sca-match

Dependency→CVE matching engine for Go. Given one resolved dependency, returns every CVE that
affects it — by four methods, recording which method matched:

- **version-range** — `CVEAffected` / `CVEAffectedVersion` with a real multi-ecosystem version
  comparator (semver, PEP 440, Maven, generic fallback): "version lower than fixed" / "within
  affected range".
- **purl** — registry-precise via `PackageVersionCVE`.
- **cpe** — `CVEAffected.cpes` / `CVEMetadata.cpesJSON` prefix match.
- **crit** — `CritRecord` tagging over already-matched CVEs.

```go
import match "github.com/Vulnetix/vdb-sca-match"

matches, err := match.MatchDependency(ctx, pool, match.Dependency{
    Name: "lodash", Version: "4.17.20", Ecosystem: "npm",
    Purl: "pkg:npm/lodash@4.17.20",
})
// each Match carries CveID, Source, Method, VulnerableRange
```

`pool` is any `*pgxpool.Pool` (or `pgx.Tx`) — both satisfy the `Querier` interface.

Shared across `vdb-sca-monitor`, `vdb-api-cyclonedx-uploads`, and `vdb-api` (`/v2/cli.sca`).
Consumed as a sibling module via `replace github.com/Vulnetix/vdb-sca-match => ../vdb-sca-match`
(the `ietf-crit-spec` pattern), cloned at container-build time.

See [PLAN.md](./PLAN.md) for the full design, SQL, and version-comparator spec.

## Reconciling sources

One advisory is stored once per source, and the sources disagree. Before a match is returned
the rows are reconciled; each rule has a test in `match_test.go` named for the real advisory
that showed the need.

- **A stated start beats a placeholder** (`dropSupersededZeroRows`): `0 .. < X` from cve.org
  or GitLab loses to `S .. < X` from a *different* source. One source stating both is the
  union, not a correction.
- **A range end is one end however it is spelled** (`canonicalUpper`): `<= 4.1.1` and
  `< 4.1.2` compare equal for plain dotted-numeric versions; anything else compares as written.
- **Backport gaps** (`applyFinerBranchRanges`, `dropEnvelopeFill`): a wide range over the
  same span another id or source states branch by branch does not cover the gap between
  branches, including a source that lists its own summary row beside its own branches.
- **Withdrawn, ecosystem authority, open ranges and non-semver versions** have their own
  rules; see the tests in `match_test.go` and `versionrange_test.go`.

Add the failing case as a test first, with the advisory id in its name.

## Safe Harbour: version order, stability and the four outcomes

`version/` also answers the questions Safe Harbour asks of a package's release history, for
every ecosystem the platform knows (`version.SchemeFor`):

- `Classify(ecosystem, v)`: is it a version of the scheme, and is it stable? A pre-release,
  snapshot, nightly, milestone or other build is not (`prerelease`, `dev`, `snapshot`,
  `nightly`, `milestone`, `git-snapshot`, `pseudo-version`, `branch-ref`, ...).
- `Order(ecosystem, a, b)`: the scheme's own ordering (PEP 440 epochs, Debian tildes,
  Maven qualifiers, RubyGems letters, Go pseudo-versions, and so on).
- `Pick(ecosystem, running, candidates)`: candidates are free of malware. `latest` and `safest`
  (the highest clean stable release, not the newest by date), `stable` (the clean stable release
  closest to `running`) and `rolling` (every version from the release day of the highest version, or the most
  recent day when versions cannot be ordered; pre-releases and exposed releases included, since only malware is excluded). A `Candidate`
  marked `Exposed` is skipped by the first three and kept by `rolling`. Release dates
  decide only what the version string cannot order.
- `EncodeRolling` / `DecodeRolling`: the comma-delimited form of a rolling set.

Sixty-seven schemes are catalogued in `version/schemes.json` (embedded, `version.Catalogue`; Ivy and Coursier are folded into Gradle and Maven)
with their sources, stable-release rules and known gaps; `docs/version-schemes.md` is generated
from it (`go run ./version/cmd/gen-schemes-doc > docs/version-schemes.md`, checked by a test).
Each scheme is held to golden vectors produced by its reference implementation wherever one
could be run (`version/testdata/scheme_vectors.json`, `pick_vectors.json`); the few vectors an
engine deliberately answers differently are listed with a reason in
`version/testdata/known_divergences.json`. Add a failing vector first.
<!-- ci-touch: 2026-08-24T20:54:39Z -->

## GitHub posture analysis (`ghaudit/`)

`ghaudit` evaluates GitHub Actions workflows, composite actions, the actions and images they
run, and repository/organisation settings, and reports misconfigurations as findings with
stable fingerprints, CWE/CWSS metadata and, where safe, line edits that fix them. It is pure:
callers supply files and optional `Facts` (collected from the REST API or the GitHub App
mirror) and render the `Report` as SARIF (`Report.SARIF`, driver `Vulnetix GitHub`, category
`IAC`) or as Finding rows. The CLI (`vulnetix gha workflows|actions|settings|org|audit`)
and the Software Factory webhook path run the same engine, so the same input produces the same
finding in both. Rule catalogue: [docs/ghaudit-rules.md](./docs/ghaudit-rules.md).
