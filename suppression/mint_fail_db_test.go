package suppression

import (
	"context"
	"errors"
	"testing"
)

type failingPutter struct{}

func (failingPutter) PutWithMetadata(context.Context, string, []byte, string, map[string]string) error {
	return errors.New("AccessDenied: s3:PutObject")
}

// A store that fails must not lose the applications or the Triage.
func TestDBMintFailureKeepsApplications(t *testing.T) {
	pool := setupDB(t)
	e := &Engine{Putter: failingPutter{}, Bucket: "b", Service: "test", Now: func() int64 { return 1000 }}
	mustExec(t, pool, `
		INSERT INTO "ScannerRun" VALUES ('run-f', 900, 'org-1', 'acme/app', NULL);
		INSERT INTO "CliScanEnvironment" VALUES ('env-f', 'org-1', 'run-f', 900, 'main', 'abc');
		INSERT INTO "Finding" (uuid, "findingId", "orgId", "repoName", source, category, "createdAt", "modifiedAt", "detectionTitle", purl, "packageName", "scannerRunUuid")
		VALUES ('f-f', 'CVE-2021-23337', 'org-1', 'acme/app', 'cli', 'sca', 900, 900, 't', 'pkg:npm/lodash@1.0.0', 'lodash', 'run-f');
	`)
	res, err := e.Apply(context.Background(), pool, Scope{OrgID: org, ScannerRunUuid: "run-f", CallSite: "cli-sca", Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if res.MintError == nil || len(res.Minted) != 0 || len(res.Applied) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if latestTriage(t, pool, "f-f") != "suppressed" {
		t.Error("triage lost with the failed mint")
	}
	if n := scalar[int](t, pool, `SELECT count(*) FROM "SuppressionApplication" WHERE "findingUuid" = 'f-f' AND "removedAt" IS NULL`); n != 1 {
		t.Errorf("applications = %d", n)
	}
}
