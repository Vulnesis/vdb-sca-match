package suppression

// Runs against a disposable Postgres:
//
//	SUPPRESSION_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:55733/postgres \
//	  go test ./suppression/ -run DB -v
//
// It loads testdata/schema.sql (the pre-migration tables), seeds legacy rows,
// then applies the real saas migration from ../saas so the backfill is tested
// too. Skipped when the variable is unset.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Vulnesis/vdb-cyclonedx/vexrules"
)

const migrationPath = "../../saas/prisma/migrations/20261217000000_suppression_provenance/migration.sql"

type fakePutter struct {
	mu   sync.Mutex
	docs map[string][]byte
}

func (p *fakePutter) PutWithMetadata(_ context.Context, key string, data []byte, _ string, _ map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.docs == nil {
		p.docs = map[string][]byte{}
	}
	p.docs[key] = append([]byte(nil), data...)
	return nil
}

const org = "org-1"

func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SUPPRESSION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SUPPRESSION_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	mustExecFile(t, pool, "testdata/schema.sql")

	// Legacy state: a console rule bound to one finding, a CLI rule anchored
	// on a rule id, and an inactive rule.
	mustExec(t, pool, `
		INSERT INTO "ScannerRun" VALUES ('run-old', 1, 'org-1', 'acme/app', NULL);
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, aliases, "packageName", "packageVersion", "scannerRunUuid")
		VALUES ('f-old', 'CVE-2021-23337', 'org-1', 'acme/app', 'cli', 'sca', 1, 1, 't', 'pkg:npm/lodash@4.17.20', '["GHSA-35jh-r3h4-6jhm"]', 'lodash', '4.17.20', 'run-old');
		INSERT INTO "Suppression" (uuid, "orgId", "findingUuid", "suppressionType", "ruleId", category, reason, "createdAt", "repositoryFullName", origin, "isActive")
		VALUES ('s-console', 'org-1', 'f-old', 'risk_accepted', 'CVE-2021-23337', 'sca', 'legacy console rule', 1, 'acme/app', 'console', true),
		       ('s-cli', 'org-1', NULL, 'rego_rule', 'go.sql-injection', 'sast', 'cli ignore', 1, 'acme/app', 'cli', true),
		       ('s-off', 'org-1', 'f-old', 'false_positive', NULL, NULL, 'old', 1, NULL, NULL, false);
	`)
	data, err := os.ReadFile(filepath.Clean(migrationPath))
	if err != nil {
		t.Skipf("saas migration not found next to vdb-sca-match: %v", err)
	}
	mustExec(t, pool, string(data))
	// The migration is idempotent: a second run must not fail or duplicate.
	mustExec(t, pool, string(data))
	// The Suppression half of saas 20261221000001_rule_suppression_cel_expr,
	// which ruleCols reads. That migration also alters RiskPrioritizationRule,
	// which this schema does not have, so it cannot be applied whole here.
	mustExec(t, pool, `ALTER TABLE "Suppression" ADD COLUMN IF NOT EXISTS expr TEXT, ADD COLUMN IF NOT EXISTS justification TEXT`)
	return pool
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("exec: %v\n%s", err, sql)
	}
}

func mustExecFile(t *testing.T, pool *pgxpool.Pool, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, string(b))
}

func scalar[T any](t *testing.T, pool *pgxpool.Pool, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return v
}

func latestTriage(t *testing.T, pool *pgxpool.Pool, finding string) string {
	t.Helper()
	return scalar[string](t, pool, `SELECT COALESCE((SELECT "analysisState" FROM "Triage" WHERE "findingUuid" = $1 ORDER BY "createdAt" DESC, uuid LIMIT 1), '')`, finding)
}

var cliActor = vexrules.NewIdentity(
	vexrules.Evidence{Kind: vexrules.EvidenceGitConfig, Email: "alice@example.com", Label: "Alice"},
	vexrules.Evidence{Kind: vexrules.EvidenceOrgKey, ID: "org-1"},
)

func TestDBMigrationBackfill(t *testing.T) {
	pool := setupDB(t)
	for uuid, want := range map[string]string{"s-console": "console", "s-cli": "cli", "s-off": "bulk"} {
		if got := scalar[string](t, pool, `SELECT "sourceKind" FROM "Suppression" WHERE uuid = $1`, uuid); got != want {
			t.Errorf("%s sourceKind = %s, want %s", uuid, got, want)
		}
	}
	if n := scalar[int](t, pool, `SELECT count(*) FROM "SuppressionApplication" WHERE "removedAt" IS NULL`); n != 1 {
		t.Errorf("live seeded applications = %d, want 1 (s-console only)", n)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO "SuppressionAudit" ("orgId","suppressionUuid",action,service,"createdAt") VALUES ('o','s','create','t',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE "SuppressionAudit" SET action = 'x'`); err == nil {
		t.Error("SuppressionAudit accepted an UPDATE")
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM "SuppressionAudit"`); err == nil {
		t.Error("SuppressionAudit accepted a DELETE")
	}
	// A scan-data purge sets the transaction-local flag and may delete.
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `SELECT set_config('vulnetix.suppression_audit_purge', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `DELETE FROM "SuppressionAudit"`); err != nil {
		t.Errorf("purge delete refused: %v", err)
	}
	_ = tx.Rollback(context.Background())
	// The rows are back; outside that transaction a DELETE is refused again.
	if _, err := pool.Exec(context.Background(), `DELETE FROM "SuppressionAudit"`); err == nil {
		t.Error("the purge flag leaked past its transaction")
	}
}

func TestDBApplyRemoveAndMint(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	put := &fakePutter{}
	e := &Engine{Putter: put, Bucket: "b", Service: "test", Now: func() int64 { return 1000 }}

	// A new scan writes a new row for the same vulnerability. Before the
	// engine, s-console covered only f-old.
	mustExec(t, pool, `
		INSERT INTO "ScannerRun" VALUES ('run-2', 900, 'org-1', 'acme/app', NULL);
		INSERT INTO "CliScanEnvironment" VALUES ('env-2', 'org-1', 'run-2', 900, 'main', 'abc123');
		INSERT INTO "IngestionSnapshot" (uuid, "createdAt", "orgId", "scannerRunUuid", "toolName") VALUES ('snap-2', 900, 'org-1', 'run-2', 'cli');
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, aliases, "packageName", "packageVersion", "scannerRunUuid") VALUES
		  ('f-new', 'CVE-2021-23337', 'org-1', 'acme/app', 'cli', 'sca', 900, 900, 't', 'pkg:npm/lodash@4.17.21', NULL, 'lodash', '4.17.21', 'run-2'),
		  ('f-other-repo', 'CVE-2021-23337', 'org-1', 'acme/web', 'cli', 'sca', 900, 900, 't', 'pkg:npm/lodash@4.17.21', NULL, 'lodash', '4.17.21', 'run-2'),
		  ('f-sast', 'go.sql-injection', 'org-1', 'acme/app', 'cli', 'sast', 900, 900, 't', NULL, NULL, 'internal/db/q.go', NULL, 'run-2');
	`)
	res, err := e.Apply(ctx, pool, Scope{OrgID: org, ScannerRunUuid: "run-2", CallSite: "cli-sca", Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 || res.Suppressed != 2 {
		t.Fatalf("applied = %+v suppressed = %d, want f-new and f-sast", res.Applied, res.Suppressed)
	}
	if latestTriage(t, pool, "f-new") != "suppressed" || latestTriage(t, pool, "f-sast") != "suppressed" || latestTriage(t, pool, "f-other-repo") != "" {
		t.Error("triage not written as expected")
	}
	if resp := scalar[string](t, pool, `SELECT COALESCE("analysisResponse",'') FROM "Triage" WHERE "findingUuid" = 'f-new'`); resp != `["will_not_fix"]` {
		t.Errorf("risk_accepted triage response = %q", resp)
	}
	if n := scalar[int](t, pool, `SELECT suppressed FROM "IngestionSnapshot" WHERE uuid = 'snap-2'`); n != 2 {
		t.Errorf("snapshot suppressed = %d", n)
	}
	if len(res.Minted) != 2 || !res.Minted[0].Grounded || res.Minted[0].GitCommit != "abc123" {
		t.Fatalf("minted = %+v", res.Minted)
	}
	if n := scalar[int](t, pool, `SELECT count(*) FROM "Artifact" WHERE "scannerRunUuid" = 'run-2' AND type = 'vex'`); n != 2 {
		t.Errorf("grounded VEX artifacts = %d", n)
	}
	if kind := scalar[string](t, pool, `SELECT "actorKind" FROM "SuppressionAudit" WHERE action = 'apply' LIMIT 1`); kind != "git_config" {
		t.Errorf("audit actor = %s", kind)
	}

	// Idempotent: the same scope again changes nothing.
	again, err := e.Apply(ctx, pool, Scope{OrgID: org, ScannerRunUuid: "run-2", CallSite: "cli-sca", Actor: cliActor})
	if err != nil || len(again.Applied) != 0 || again.Suppressed != 2 {
		t.Fatalf("second apply = %+v, %v", again, err)
	}

	// The minted document links back to its rule when ingested again.
	var minted []byte
	for _, d := range put.docs {
		if strings.Contains(string(d), "s-console") {
			minted = d
		}
	}
	in, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: minted, Origin: "scan_vex_file", ScannerRunUuid: "run-2", Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Linked) != 1 || in.Linked[0] != "s-console" || len(in.Created) != 0 {
		t.Fatalf("re-ingest of our own VEX = %+v", in)
	}

	// Deactivating the rule returns its findings to triage.
	n, err := e.Remove(ctx, pool, org, "s-console", "deactivated", cliActor)
	if err != nil || n != 2 {
		t.Fatalf("remove = %d, %v", n, err)
	}
	if latestTriage(t, pool, "f-new") != "in_triage" {
		t.Error("f-new not returned to triage")
	}
	if got := scalar[int](t, pool, `SELECT suppressed FROM "IngestionSnapshot" WHERE uuid = 'snap-2'`); got != 1 {
		t.Errorf("snapshot after remove = %d, want 1 (f-sast still covered)", got)
	}
}

const cdxFP = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:fp",
 "metadata":{"timestamp":"2026-10-01T00:00:00Z","authors":[{"name":"Acme PSIRT"}]},
 "components":[{"bom-ref":"c1","purl":"pkg:npm/minimist@1.2.5"}],
 "vulnerabilities":[{"id":"CVE-2021-44906","analysis":{"state":"false_positive","detail":"not in the bundle","lastUpdated":"2026-10-01T00:00:00Z"},"affects":[{"ref":"c1"}]}]}`

const openvexWontFix = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme/vex/2","author":"Acme",
 "timestamp":"2026-10-01T00:00:00Z","statements":[{"@id":"s1","vulnerability":{"name":"CVE-2022-0001"},
 "products":[{"@id":"pkg:npm/left-pad@1.0.0"}],"status":"affected","action_statement":"Will not fix: vendor EOL"}]}`

func openvexNotAffected(ts string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme/vex/` + ts + `","author":"Acme",
 "timestamp":"` + ts + `","statements":[{"@id":"s1","vulnerability":{"name":"CVE-2021-44906"},
 "products":[{"@id":"pkg:npm/minimist@1.2.5"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
}

func TestDBIngestAndSupersede(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	e := &Engine{Putter: &fakePutter{}, Bucket: "b", Service: "test", Now: func() int64 { return 2000 }}
	mustExec(t, pool, `
		INSERT INTO "ScannerRun" VALUES ('run-3', 1900, 'org-1', 'acme/app', NULL);
		INSERT INTO "CliScanEnvironment" VALUES ('env-3', 'org-1', 'run-3', 1900, 'main', 'def456');
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, aliases, "packageName", "packageVersion", "scannerRunUuid") VALUES
		  ('f-min', 'CVE-2021-44906', 'org-1', 'acme/app', 'cli', 'sca', 1900, 1900, 't', 'pkg:npm/minimist@1.2.5', NULL, 'minimist', '1.2.5', 'run-3'),
		  ('f-min-web', 'CVE-2021-44906', 'org-1', 'acme/web', 'cli', 'sca', 1900, 1900, 't', 'pkg:npm/minimist@1.2.5', NULL, 'minimist', '1.2.5', 'run-3'),
		  ('f-pad', 'CVE-2022-0001', 'org-1', 'acme/app', 'cli', 'sca', 1900, 1900, 't', 'pkg:npm/left-pad@1.0.0', NULL, 'left-pad', '1.0.0', 'run-3');
		INSERT INTO "Member" (uuid, email, "orgId") VALUES ('m-alice', 'alice@example.com', 'org-1');
	`)

	res, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(cdxFP), Origin: "scan_vex_file", ScannerRunUuid: "run-3", Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Grounded || len(res.Created) != 1 || res.Applied != 1 {
		t.Fatalf("CDX false positive ingest = %+v", res)
	}
	rule := res.Created[0]
	if got := scalar[string](t, pool, `SELECT "sourceKind" || '/' || "matchBasis" || '/' || "repositoryFullName" || '/' || "createdBy" FROM "Suppression" WHERE uuid = $1`, rule); got != "vex/structured/acme/app/m-alice" {
		t.Errorf("rule provenance = %s", got)
	}
	if latestTriage(t, pool, "f-min") != "suppressed" || latestTriage(t, pool, "f-min-web") != "" {
		t.Error("repo scope not honoured")
	}

	pend, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(openvexWontFix), Origin: "upload", Repository: "acme/app", Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if len(pend.Pending) != 1 || len(pend.Created) != 0 || latestTriage(t, pool, "f-pad") != "" {
		t.Fatalf("text-basis won't fix must wait for review: %+v", pend)
	}
	if pend.Grounded {
		t.Error("an upload with no scanner run is not grounded")
	}

	// An older statement arriving later changes nothing.
	old, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(openvexNotAffected("2026-09-01T00:00:00Z")), Origin: "upload", Repository: "acme/app", Actor: cliActor})
	if err != nil || len(old.Superseded) != 0 {
		t.Fatalf("older statement superseded the rule: %+v %v", old, err)
	}
	if !scalar[bool](t, pool, `SELECT "isActive" FROM "Suppression" WHERE uuid = $1`, rule) {
		t.Fatal("rule deactivated by an older statement")
	}

	// A newer one withdraws it, and the finding takes the new state.
	newer, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(openvexNotAffected("2026-11-01T00:00:00Z")), Origin: "upload", Repository: "acme/app", Actor: cliActor})
	if err != nil || len(newer.Superseded) != 1 || newer.Superseded[0] != rule {
		t.Fatalf("newer statement = %+v %v", newer, err)
	}
	if scalar[bool](t, pool, `SELECT "isActive" FROM "Suppression" WHERE uuid = $1`, rule) {
		t.Error("superseded rule still active")
	}
	if got := latestTriage(t, pool, "f-min"); got != "not_affected" {
		t.Errorf("f-min triage after supersede = %s", got)
	}

	// VEX never touches a console rule.
	mustExec(t, pool, `UPDATE "Suppression" SET "vulnerabilityId" = 'CVE-2021-44906', "productPurlBase" = 'pkg:npm/minimist' WHERE uuid = 's-console'`)
	if _, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(openvexNotAffected("2026-12-01T00:00:00Z")), Origin: "upload", Repository: "acme/app", Actor: cliActor}); err != nil {
		t.Fatal(err)
	}
	if !scalar[bool](t, pool, `SELECT "isActive" FROM "Suppression" WHERE uuid = 's-console'`) {
		t.Error("VEX deactivated a console rule")
	}
}
