# Suppression engine (`suppression/`)

Last Updated: 2026-11-02

One engine decides which suppression rules cover which findings, for every service that
writes a `Finding` row: vdb-api (`/v2/cli.*`), vdb-site (console, uploads, integrations),
vdb-api-cyclonedx-uploads and vdb-sca-monitor. The statement classifier, markers, rule
matcher and identity ladder are the public `github.com/Vulnetix/vdb-cyclonedx/vexrules`
package; this package is the SQL against the saas schema.

## Entry points

| Method | Called when | What it does |
|---|---|---|
| `Apply(ctx, db, Scope)` | after any code path writes findings | Matches the active, unexpired rules of the org against the findings in scope (`ScannerRunUuid` or `FindingUuids`) and records each match |
| `ApplyRule(ctx, db, org, rule, actor)` | a rule is created, extended, approved or reactivated | Applies one rule to the org's existing findings (at most 5000 per call) |
| `Remove(ctx, db, org, rule, reason, actor)` | a rule is deactivated, rejected or superseded | Sets `removedAt` on its applications and returns each finding's Triage to `in_triage` unless another rule still covers it |
| `Ingest(ctx, db, IngestInput)` | a VEX document arrives (CLI, upload, BOM analysis) | Parses, classifies, stores `OpenVex` and `OpenVexStatement` rows, creates or supersedes rules, writes Triage evidence |
| `WriteAudit` | any of the above | Appends `SuppressionAudit` rows |

## Recording a match

For each (rule, finding) pair, inside a savepoint of the caller's transaction:

1. Upsert `SuppressionApplication` (unique on rule and finding). Read paths follow this
   table, so a rule covers the rows each new scan writes.
2. Write a `suppressed` Triage row. A false positive reads
   `vulnerable_code_not_present`, a mitigation `protected_by_mitigating_control`,
   anything else carries the response `will_not_fix`.
3. Append a `SuppressionAudit` `apply` row with the actor.
4. Set `IngestionSnapshot.suppressed`.
5. Mint one CycloneDX VEX per (run, rule) in a nested savepoint. A failed mint (for
   example an S3 put the service's role cannot make) is returned as `Result.MintError` and
   keeps the applications and Triage.

Triage rows the engine writes use `GREATEST(now, max(createdAt)+1)`, so they sort as the
latest row for the finding. `Triage.createdAt` is milliseconds in vdb-api and seconds in
vdb-site; that mix predates the engine and is not fixed here.

## Matching

A rule matches a finding when its `findingUuid` is that finding, or `vexrules.RuleMatches`
accepts it: the vulnerability id against the finding id and aliases, the product purl base,
the repository scope and the rule's own target. A VEX rule is scoped to the repository it was
ingested from; with no repository it is org-wide, still limited to its vulnerability and purl.

## VEX ingest

- Only `false_positive` and `wont_fix` dispositions become rules. Every other state is stored
  as an `OpenVexStatement` and written as Triage evidence; a person's own triage decision is
  never overwritten.
- A won't fix read from OpenVEX prose (`matchBasis = text`) is created inactive with
  `reviewState = pending`.
- A `vulnetix:suppression/uuid` marker the org owns links the statement to that rule instead
  of creating one, so re-ingesting a Vulnesis VEX adds a `link` audit row and nothing else.
- A newer statement (by statement timestamp) supersedes an older VEX rule for the same
  vulnerability, purl base and repository, whatever order they arrive in. VEX never
  supersedes `console`, `cli`, `cli_ignore`, `nosec` or `bulk` rules, nor a rule that came
  from a marker.

## Grounding and TEA

A minted VEX is grounded when its run has `ScannerRun.repoName` and
`CliScanEnvironment.gitCommit`; when the finding's own run has neither, the latest grounded
run for the same repository is used. A grounded mint is an `Artifact` of type `vex` with the
run's `scannerRunUuid`, which the TEA projection picks up. An ungrounded VEX is stored with
`OpenVex.grounded = false` and never reaches TEA; publish it by hand with
`vulnetix tea publish`.

## Tests

```sh
go test ./suppression/...
podman run -d --name vexsupp-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55733:5432 pgvector/pgvector:pg17
SUPPRESSION_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:55733/postgres go test -count=1 ./suppression/
```

The DB tests load `testdata/schema.sql` (the tables before the migration) and then the saas
migration `20261217000000_suppression_provenance` twice, to show it re-runs. The saas
migration history does not replay from an empty database, so the fixture stands in for it.
Update the fixture when a table the engine touches changes shape.
