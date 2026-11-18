package suppression

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Vulnesis/vdb-cyclonedx/vexrules"
)

// Runs with the other DB tests (SUPPRESSION_TEST_DATABASE_URL).

func seedDeferFindings(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO "ScannerRun" VALUES ('run-d', 1900, 'org-1', 'acme/app', NULL);
		INSERT INTO "CliScanEnvironment" VALUES ('env-d', 'org-1', 'run-d', 1900, 'main', 'def456');
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, aliases, "packageName", "packageVersion", "scannerRunUuid") VALUES
		  ('f-min', 'CVE-2021-44906', 'org-1', 'acme/app', 'cli', 'sca', 1900, 1900, 't', 'pkg:npm/minimist@1.2.5', NULL, 'minimist', '1.2.5', 'run-d'),
		  ('f-min-ghsa', 'GHSA-xvch-5gv4-984h', 'org-1', 'acme/app', 'cli', 'sca', 1900, 1900, 't', 'pkg:npm/minimist@1.2.5', '["CVE-2021-44906"]', 'minimist', '1.2.5', 'run-d');
	`)
}

// A deferred ingest writes the rules and nothing on the findings; the follow-ups
// then do exactly what the in-transaction ingest would have done.
func TestDBIngestDeferFindingWork(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	e := &Engine{Putter: &fakePutter{}, Bucket: "b", Service: "test", Now: func() int64 { return 2000 }}
	seedDeferFindings(t, pool)

	res, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(cdxFP), Origin: "scan_vex_file",
		ScannerRunUuid: "run-d", Actor: cliActor, DeferFindingWork: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 || res.Applied != 0 {
		t.Fatalf("deferred ingest = %+v, want one rule and nothing applied yet", res)
	}
	rule := res.Created[0]
	if !scalar[bool](t, pool, `SELECT "isActive" FROM "Suppression" WHERE uuid = $1`, rule) {
		t.Fatal("the rule must be live when Ingest returns")
	}
	if n := scalar[int](t, pool, `SELECT count(*) FROM "SuppressionApplication" WHERE "suppressionUuid" = $1`, rule); n != 0 {
		t.Fatalf("deferred ingest wrote %d applications", n)
	}
	if latestTriage(t, pool, "f-min") != "" {
		t.Fatal("deferred ingest wrote Triage")
	}
	if len(res.FollowUps) != 1 || res.FollowUps[0].Kind != FollowUpApply || res.FollowUps[0].RuleUuid != rule || res.FollowUps[0].OrgID != org {
		t.Fatalf("follow-ups = %+v", res.FollowUps)
	}

	out := e.RunFollowUps(ctx, pool, res.FollowUps, cliActor)
	if len(out.Errors) != 0 {
		t.Fatal(out.Errors)
	}
	// The GHSA row lists the CVE as an alias, so the rule covers it too.
	if out.Applied != 2 {
		t.Fatalf("follow-ups applied %d, want 2 (f-min and its GHSA alias row)", out.Applied)
	}
	for _, f := range []string{"f-min", "f-min-ghsa"} {
		if latestTriage(t, pool, f) != "suppressed" {
			t.Errorf("%s not suppressed after the follow-ups", f)
		}
	}
	// Running them again is a no-op.
	if again := e.RunFollowUps(ctx, pool, res.FollowUps, cliActor); again.Applied != 0 || len(again.Errors) != 0 {
		t.Errorf("second run = %+v", again)
	}

	// A newer triage-only statement supersedes the rule: the follow-ups end
	// its applications first, then write the statement's state, so that
	// state is the findings' latest Triage.
	newer, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(openvexNotAffected("2026-11-01T00:00:00Z")),
		Origin: "upload", Repository: "acme/app", Actor: cliActor, DeferFindingWork: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(newer.Superseded) != 1 || scalar[bool](t, pool, `SELECT "isActive" FROM "Suppression" WHERE uuid = $1`, rule) {
		t.Fatalf("supersede must take effect on the rule at once: %+v", newer)
	}
	if latestTriage(t, pool, "f-min") != "suppressed" {
		t.Fatal("deferred supersede touched Triage")
	}
	kinds := []FollowUpKind{}
	for _, f := range newer.FollowUps {
		kinds = append(kinds, f.Kind)
	}
	if len(kinds) != 2 || kinds[0] != FollowUpRemove || kinds[1] != FollowUpEvidence {
		t.Fatalf("follow-up order = %v, want remove then evidence", kinds)
	}
	out = e.RunFollowUps(ctx, pool, newer.FollowUps, cliActor)
	if len(out.Errors) != 0 || out.Removed != 2 {
		t.Fatalf("supersede follow-ups = %+v", out)
	}
	if got := latestTriage(t, pool, "f-min"); got != "not_affected" {
		t.Errorf("f-min triage = %s, want not_affected", got)
	}
}

// A failed step is reported and does not stop the ones after it.
func TestDBRunFollowUpsContinuesPastAFailure(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	e := &Engine{Service: "test", Now: func() int64 { return 2000 }}
	seedDeferFindings(t, pool)
	res, err := e.Ingest(ctx, pool, IngestInput{OrgID: org, Data: []byte(cdxFP), Origin: "scan_vex_file",
		ScannerRunUuid: "run-d", Actor: cliActor, DeferFindingWork: true})
	if err != nil {
		t.Fatal(err)
	}
	work := append([]FollowUp{{Kind: "bogus", OrgID: org, RuleUuid: "x"}}, res.FollowUps...)
	out := e.RunFollowUps(ctx, pool, work, cliActor)
	if len(out.Errors) != 1 || out.Applied != 2 {
		t.Fatalf("out = %+v", out)
	}
}

// Newer findings of the same product for other vulnerabilities must not fill
// the cap: they used to come back through the product branch of the OR, and
// the rule's own findings, being older, fell off the end.
func TestDBApplyRuleIgnoresOtherVulnerabilitiesOfTheProduct(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	e := &Engine{Service: "test", Now: func() int64 { return 99999 }}
	seedDeferFindings(t, pool)
	mustExec(t, pool, `
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, aliases, "packageName", "packageVersion", "scannerRunUuid")
		SELECT 'noise-' || g, 'CVE-2099-' || g, 'org-1', 'acme/app', 'cli', 'sca', 5000 + g, 5000 + g, 't', 'pkg:npm/minimist@1.2.5', '["GHSA-noise"]', 'minimist', '1.2.5', 'run-d'
		FROM generate_series(1, 5001) g;
		INSERT INTO "Suppression" (uuid, "orgId", "suppressionType", reason, "createdAt", "repositoryFullName", origin, "isActive", "vulnerabilityId", "productPurlBase", "sourceKind")
		VALUES ('s-vex', 'org-1', 'false_positive', 'r', 1, 'acme/app', 'vex', true, 'CVE-2021-44906', 'pkg:npm/minimist', 'vex');
	`)
	res, err := e.ApplyRule(ctx, pool, org, "s-vex", cliActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("applied %d, want f-min and f-min-ghsa", len(res.Applied))
	}
}

// The prefilters must be answerable from the indexes. Seq scans are disabled,
// so a plan without the index means the predicate no longer matches the index
// expression and production would read every Finding row of the org again.
// Each check runs in a transaction that is rolled back; the alias check drops
// the btree indexes there, which on a table this small the planner would
// otherwise prefer to the trigram index whatever the predicate.
func TestDBFindingLookupsUseIndexes(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	explain := func(prep, q string, args ...any) string {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off; `+prep); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.Query(ctx, "EXPLAIN "+q, args...)
		if err != nil {
			t.Fatalf("explain: %v\n%s", err, q)
		}
		defer rows.Close()
		var b strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			b.WriteString(line + "\n")
		}
		return b.String()
	}

	q, args := ruleFindingQuery(org, ruleRow{Rule: vexrules.Rule{VulnerabilityID: "CVE-2021-44906", ProductPurlBase: "pkg:npm/minimist"}}, maxRuleChangeFindings)
	if plan := explain("", q, args...); !strings.Contains(plan, `Index Cond: (("orgId" = 'org-1'::text) AND (lower("findingId") = ANY`) {
		t.Errorf("ApplyRule id branch is not an index lookup on Finding_orgId_lowerFindingId_createdAt_idx:\n%s", plan)
	}
	if plan := explain(`DROP INDEX "Finding_orgId_idx"; DROP INDEX "Finding_orgId_lowerFindingId_createdAt_idx"`, q, args...); !strings.Contains(plan, "Bitmap Index Scan on \"Finding_lowerAliases_trgm_idx\"") {
		t.Errorf("ApplyRule alias branch cannot use Finding_lowerAliases_trgm_idx:\n%s", plan)
	}
	if plan := explain("", evidenceFindingsSQL, org, []string{"cve-2021-44906"}, maxRuleChangeFindings); !strings.Contains(plan, `Index Cond: (("orgId" = 'org-1'::text) AND (lower("findingId") = ANY`) {
		t.Errorf("evidence lookup is not an index lookup on Finding_orgId_lowerFindingId_createdAt_idx:\n%s", plan)
	}
}
