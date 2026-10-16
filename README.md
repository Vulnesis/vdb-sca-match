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
<!-- ci-touch: 2026-08-24T20:54:39Z -->
