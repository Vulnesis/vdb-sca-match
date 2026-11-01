package suppression

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// maxRuleChangeFindings caps how many findings one rule change evaluates. A
// rule names a vulnerability or a rule id, and the org's newest rows for it are
// what the console shows; older rows are covered by the next scan or by the
// vdb-api suppression-apply-sweep command.
const maxRuleChangeFindings = 5000

// ApplyRule applies one rule to the org's existing findings. Call it after a
// rule is created, extended, approved or reactivated.
func (e *Engine) ApplyRule(ctx context.Context, db Beginner, orgID, suppressionUuid string, actor vexrules.Identity) (Result, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := e.now()

	rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM "Suppression" s
		WHERE s.uuid = $1 AND s."orgId" = $2 AND s."isActive" AND (s."expiresAt" IS NULL OR s."expiresAt" > $3)`,
		suppressionUuid, orgID, now)
	if err != nil {
		return Result{}, err
	}
	rules, err := scanRules(rows)
	if err != nil || len(rules) == 0 {
		return Result{}, err
	}
	r := rules[0]

	ids := []string{}
	for _, id := range []string{r.Rule.RuleID, r.Rule.FindingID, r.Rule.VulnerabilityID} {
		if id = strings.ToLower(vexrules.NormalizeVulnID(id)); id != "" {
			ids = append(ids, id)
		}
	}
	purlBase := vexrules.PurlBase(r.Rule.ProductPurlBase)
	if purlBase == "" && r.Rule.TargetValue != "" {
		purlBase = vexrules.PurlBase(r.Rule.TargetValue)
	}
	// Prefilter in SQL on whichever anchor the rule has. Aliases are a JSON
	// array of strings, so an id is searched as a quoted element.
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, `%"`+id+`"%`)
	}
	fileSuffix := ""
	if fp := strings.Trim(strings.ReplaceAll(r.Rule.FilePath, `\`, "/"), "/"); fp != "" {
		fileSuffix = "%" + strings.TrimPrefix(fp, "./")
	}
	rows, err = tx.Query(ctx, `SELECT `+findingCols+` FROM "Finding" f
		WHERE f."orgId" = $1
		  AND ( f.uuid = $2
		     OR lower(f."findingId") = ANY($3)
		     OR lower(COALESCE(f.aliases,'')) LIKE ANY($4)
		     OR ($5 <> '' AND lower(f.purl) LIKE lower($5) || '%')
		     OR ($6 <> '' AND f."packageName" LIKE $6)
		     OR ($7 <> '' AND lower(f.purl) = lower($7)) )
		ORDER BY f."createdAt" DESC
		LIMIT $8`,
		orgID, r.FindingUuid, ids, quoted, purlBase, fileSuffix, r.Rule.TargetValue, maxRuleChangeFindings)
	if err != nil {
		return Result{}, err
	}
	findings, err := scanFindings(rows)
	if err != nil {
		return Result{}, err
	}
	res, err := e.record(ctx, tx, Scope{OrgID: orgID, CallSite: "rule-change", Actor: actor}, findings, rules, now)
	if err != nil {
		return Result{}, err
	}
	runs := map[string]bool{}
	for _, a := range res.Applied {
		if a.ScannerRunUuid != "" && !runs[a.ScannerRunUuid] {
			runs[a.ScannerRunUuid] = true
			if err := updateSnapshotCount(ctx, tx, orgID, a.ScannerRunUuid); err != nil {
				return Result{}, err
			}
		}
	}
	return res, tx.Commit(ctx)
}

// Remove ends every live application of a rule (deactivate, supersede,
// delete) and returns each finding no other rule still covers to in_triage.
// It writes no VEX: withdrawing a suppression is not a new claim about the
// finding.
func (e *Engine) Remove(ctx context.Context, db Beginner, orgID, suppressionUuid, reason string, actor vexrules.Identity) (int, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := e.now()

	rows, err := tx.Query(ctx, `UPDATE "SuppressionApplication" SET "removedAt" = $3, "removedReason" = $4
		WHERE "suppressionUuid" = $1 AND "orgId" = $2 AND "removedAt" IS NULL
		RETURNING "findingUuid", COALESCE("scannerRunUuid",'')`, suppressionUuid, orgID, now, nz(reason))
	if err != nil {
		return 0, err
	}
	var findingUuids []string
	runs := map[string]bool{}
	for rows.Next() {
		var f, run string
		if err := rows.Scan(&f, &run); err != nil {
			rows.Close()
			return 0, err
		}
		findingUuids = append(findingUuids, f)
		if run != "" {
			runs[run] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	b := &pgx.Batch{}
	for _, f := range findingUuids {
		b.Queue(`INSERT INTO "Triage" (uuid, "findingUuid", "createdAt", "lastObserved", seen, "analysisState", "analysisDetail", "triageAutomated")
			SELECT $1, $2, GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), false, 'in_triage', $4, true
			WHERE COALESCE((SELECT "analysisState" FROM "Triage" WHERE "findingUuid" = $2 ORDER BY "createdAt" DESC LIMIT 1), '') = 'suppressed'
			  AND NOT EXISTS (SELECT 1 FROM "SuppressionApplication" sa JOIN "Suppression" s ON s.uuid = sa."suppressionUuid"
			                  WHERE sa."findingUuid" = $2 AND sa."removedAt" IS NULL AND s."isActive"
			                    AND (s."expiresAt" IS NULL OR s."expiresAt" > $3))`,
			uuid.NewString(), f, now, "Suppression rule "+suppressionUuid+" no longer applies")
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return 0, fmt.Errorf("triage: %w", err)
	}
	for run := range runs {
		if err := updateSnapshotCount(ctx, tx, orgID, run); err != nil {
			return 0, err
		}
	}
	if len(findingUuids) > 0 {
		if err := writeAudit(ctx, tx, e.Service, actorOf(actor), []AuditEntry{{
			OrgID: orgID, SuppressionUuid: suppressionUuid, Action: "unapply",
			FromValue: fmt.Sprintf("%d findings", len(findingUuids)), Reason: reason,
		}}, now); err != nil {
			return 0, err
		}
	}
	return len(findingUuids), tx.Commit(ctx)
}
