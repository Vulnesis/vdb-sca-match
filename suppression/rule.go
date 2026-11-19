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

	q, args := ruleFindingQuery(orgID, r, maxRuleChangeFindings)
	rows, err = tx.Query(ctx, q, args...)
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

// ruleFindingQuery is the SQL prefilter for the findings a rule can cover.
//
// vexrules.RuleMatches requires every anchor a rule has, so a finding it
// covers must satisfy any one of them; the prefilter selects on the most
// selective one only. It used to OR every anchor, which returned every finding
// of the product whatever its vulnerability (filling the cap with rows the
// matcher then threw away), and put an unindexable LIKE in the same predicate,
// so the planner read every Finding row the org had. On a large org that took
// longer than the request it ran in.
//
//   - an id (rule, finding or vulnerability id): the findings with that id,
//     from Finding_orgId_lowerFindingId_createdAt_idx, and the findings that
//     list it as an alias, from Finding_lowerAliases_trgm_idx
//   - otherwise a target value: the findings with that purl
//   - otherwise a file path: the findings in that file
//
// A rule bound to one finding always takes that finding as well. Each branch
// is capped on its own, and the union is capped at limit, newest first.
func ruleFindingQuery(orgID string, r ruleRow, limit int) (string, []any) {
	args := []any{orgID, limit}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	branch := func(where string) string {
		return `(SELECT uuid FROM "Finding" WHERE "orgId" = $1 AND ` + where + ` ORDER BY "createdAt" DESC LIMIT $2)`
	}
	var branches []string
	if r.FindingUuid != "" {
		branches = append(branches, branch(`uuid = `+arg(r.FindingUuid)))
	}

	ids := []string{}
	seen := map[string]bool{}
	for _, id := range []string{r.Rule.RuleID, r.Rule.FindingID, r.Rule.VulnerabilityID} {
		if id = strings.ToLower(vexrules.NormalizeVulnID(id)); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	fp := strings.TrimPrefix(strings.Trim(strings.ReplaceAll(r.Rule.FilePath, `\`, "/"), "/"), "./")
	switch {
	case len(ids) > 0:
		branches = append(branches, branch(`lower("findingId") = ANY(`+arg(ids)+`)`))
		// Aliases are a JSON array of strings, so an id is searched as a
		// quoted element. The IS NOT NULL is the trigram index's predicate.
		quoted := make([]string, 0, len(ids))
		for _, id := range ids {
			quoted = append(quoted, `%"`+likeEscape(id)+`"%`)
		}
		branches = append(branches, branch(`aliases IS NOT NULL AND lower(aliases) LIKE ANY(`+arg(quoted)+`)`))
	case r.Rule.TargetValue != "":
		branches = append(branches, branch(`lower(purl) = lower(`+arg(r.Rule.TargetValue)+`)`))
	case fp != "":
		branches = append(branches, branch(`"packageName" LIKE `+arg("%"+likeEscape(fp))))
	}
	if len(branches) == 0 {
		// No anchor: RuleMatches covers nothing, so select nothing.
		branches = append(branches, `(SELECT uuid FROM "Finding" WHERE false)`)
	}
	return `SELECT ` + findingCols + ` FROM "Finding" f
		WHERE f."orgId" = $1 AND f.uuid IN (` + strings.Join(branches, " UNION ALL ") + `)
		ORDER BY f."createdAt" DESC
		LIMIT $2`, args
}

// likeEscape quotes LIKE's wildcards (and its escape character) in s.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
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
