package suppression

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// findingRow is a Finding as the matcher needs it.
type findingRow struct {
	UUID, FindingID, Category, Aliases, Purl, PackageName, PackageVersion, Repo, ScannerRun string
}

func (f findingRow) toMatch() vexrules.Finding {
	var aliases []string
	if strings.TrimSpace(f.Aliases) != "" {
		_ = json.Unmarshal([]byte(f.Aliases), &aliases)
	}
	m := vexrules.Finding{
		UUID:       f.UUID,
		Category:   f.Category,
		RuleID:     f.FindingID,
		FindingID:  f.FindingID,
		Aliases:    aliases,
		Purl:       f.Purl,
		Value:      f.Purl,
		Repository: f.Repo,
	}
	// SAST-family findings store the file in packageName (insertSARIFFindings),
	// so a path-anchored rule (nosec, an ignore on a file) matches it.
	if f.Purl == "" && f.PackageName != "" && f.PackageName != f.FindingID {
		m.FilePath = f.PackageName
	}
	return m
}

// ruleRow is a Suppression as the matcher needs it.
type ruleRow struct {
	Rule        vexrules.Rule
	FindingUuid string
	Reason      string
	SourceKind  string
	// Expr is the rule's when (CEL), empty for most rules.
	Expr string
}

const findingCols = `f.uuid, f."findingId", f.category, COALESCE(f.aliases,''), COALESCE(f.purl,''),
	COALESCE(f."packageName",''), COALESCE(f."packageVersion",''), COALESCE(f."repoName",''), COALESCE(f."scannerRunUuid",'')`

func scanFindings(rows pgx.Rows) ([]findingRow, error) {
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.UUID, &f.FindingID, &f.Category, &f.Aliases, &f.Purl, &f.PackageName, &f.PackageVersion, &f.Repo, &f.ScannerRun); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadScopeFindings(ctx context.Context, tx pgx.Tx, s Scope) ([]findingRow, error) {
	if len(s.FindingUuids) > 0 {
		rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM "Finding" f WHERE f."orgId" = $1 AND f.uuid = ANY($2)`, s.OrgID, s.FindingUuids)
		if err != nil {
			return nil, err
		}
		return scanFindings(rows)
	}
	if s.ScannerRunUuid == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+findingCols+` FROM "Finding" f WHERE f."orgId" = $1 AND f."scannerRunUuid" = $2`, s.OrgID, s.ScannerRunUuid)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

const ruleCols = `s.uuid, s."suppressionType", COALESCE(s."ruleId",''), COALESCE(s.category,''), COALESCE(s."findingUuid",''),
	COALESCE(s."targetValue",''), COALESCE(s."filePath",''), COALESCE(s."lineRange",''), COALESCE(s."vulnerabilityId",''),
	COALESCE(s."productPurlBase",''), COALESCE(s."repositoryFullName",''), COALESCE(s."branchName",''),
	COALESCE(s."expiresAt",0), s."isActive", COALESCE(s.reason,''), COALESCE(s."sourceKind",''),
	COALESCE(s.expr,'')`

func scanRules(rows pgx.Rows) ([]ruleRow, error) {
	defer rows.Close()
	var out []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.Rule.UUID, &r.Rule.Type, &r.Rule.RuleID, &r.Rule.Category, &r.FindingUuid,
			&r.Rule.TargetValue, &r.Rule.FilePath, &r.Rule.LineRange, &r.Rule.VulnerabilityID,
			&r.Rule.ProductPurlBase, &r.Rule.RepositoryFullName, &r.Rule.Branch,
			&r.Rule.ExpiresAt, &r.Rule.IsActive, &r.Reason, &r.SourceKind, &r.Expr); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadCandidateRules prefilters the org's live rules to those that could match
// any of the findings. The Go matcher makes the final decision.
func loadCandidateRules(ctx context.Context, tx pgx.Tx, orgID string, findings []findingRow, now int64) ([]ruleRow, error) {
	uuids := make([]string, 0, len(findings))
	idSet := map[string]bool{}
	for _, f := range findings {
		uuids = append(uuids, f.UUID)
		m := f.toMatch()
		idSet[strings.ToLower(m.FindingID)] = true
		for _, a := range m.Aliases {
			idSet[strings.ToLower(vexrules.NormalizeVulnID(a))] = true
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		if id != "" {
			ids = append(ids, id)
		}
	}
	rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM "Suppression" s
		WHERE s."orgId" = $1 AND s."isActive" AND (s."expiresAt" IS NULL OR s."expiresAt" > $2)
		  AND ( s."findingUuid" = ANY($3)
		     OR lower(s."ruleId") = ANY($4)
		     OR lower(s."vulnerabilityId") = ANY($4)
		     OR (s."ruleId" IS NULL AND s."vulnerabilityId" IS NULL AND s."findingUuid" IS NULL
		         AND (s."targetValue" IS NOT NULL OR s."filePath" IS NOT NULL)) )`,
		orgID, now, uuids, ids)
	if err != nil {
		return nil, err
	}
	return scanRules(rows)
}

// matches reports whether the rule covers the finding. An exact findingUuid
// binding always matches; otherwise the shared matcher decides.
func matches(r ruleRow, f findingRow) bool {
	if r.FindingUuid != "" && r.FindingUuid == f.UUID {
		return true
	}
	return vexrules.RuleMatches(r.Rule, f.toMatch())
}

// Apply evaluates the org's live rules against the findings in scope, records
// an application for each match, writes Triage "suppressed" where it changed,
// updates the run's IngestionSnapshot.suppressed count and mints a VEX for the
// new applications.
func (e *Engine) Apply(ctx context.Context, db Beginner, s Scope) (Result, error) {
	if s.OrgID == "" {
		return Result{}, fmt.Errorf("suppression.Apply: no org")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	findings, err := loadScopeFindings(ctx, tx, s)
	if err != nil {
		return Result{}, fmt.Errorf("load findings: %w", err)
	}
	if len(findings) == 0 {
		return Result{}, tx.Commit(ctx)
	}
	now := e.now()
	rules, err := loadCandidateRules(ctx, tx, s.OrgID, findings, now)
	if err != nil {
		return Result{}, fmt.Errorf("load rules: %w", err)
	}
	res, err := e.record(ctx, tx, s, findings, rules, now)
	if err != nil {
		return Result{}, err
	}
	if s.ScannerRunUuid != "" {
		if err := updateSnapshotCount(ctx, tx, s.OrgID, s.ScannerRunUuid); err != nil {
			return Result{}, fmt.Errorf("snapshot count: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return res, nil
}

// rulePair is one rule whose anchors match one finding.
type rulePair struct {
	r ruleRow
	f findingRow
}

// keepHolding drops the pairs whose rule has a when expression that does not
// hold for the finding. The anchors decide first, in matches; the expression
// is then evaluated over the findings they matched, in one evaluator call per
// rule rather than one per pair. A rule the evaluator cannot decide (no
// evaluator, or an error, which is returned) covers nothing.
func (e *Engine) keepHolding(ctx context.Context, tx pgx.Tx, orgID string, pairs []rulePair) ([]rulePair, error) {
	conditional := map[string][]string{}
	var order []ruleRow
	for _, p := range pairs {
		if p.r.Expr == "" {
			continue
		}
		if _, seen := conditional[p.r.Rule.UUID]; !seen {
			order = append(order, p.r)
		}
		conditional[p.r.Rule.UUID] = append(conditional[p.r.Rule.UUID], p.f.UUID)
	}
	if len(order) == 0 {
		return pairs, nil
	}
	var firstErr error
	holds := map[string]map[string]bool{}
	for _, r := range order {
		if e.Conditions == nil {
			continue
		}
		h, err := e.Conditions.Holds(ctx, tx, orgID, r.Expr, conditional[r.Rule.UUID])
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rule %s: %w", r.Rule.UUID, err)
			}
			continue
		}
		holds[r.Rule.UUID] = h
	}
	kept := pairs[:0]
	for _, p := range pairs {
		if p.r.Expr != "" && !holds[p.r.Rule.UUID][p.f.UUID] {
			continue
		}
		kept = append(kept, p)
	}
	return kept, firstErr
}

// record writes applications, Triage, audit rows and the minted VEX for the
// given findings and rules.
func (e *Engine) record(ctx context.Context, tx pgx.Tx, s Scope, findings []findingRow, rules []ruleRow, now int64) (Result, error) {
	var res Result
	covered := map[string]bool{}
	var pairs []rulePair
	for _, f := range findings {
		for _, r := range rules {
			if matches(r, f) {
				pairs = append(pairs, rulePair{r, f})
			}
		}
	}
	pairs, res.ConditionError = e.keepHolding(ctx, tx, s.OrgID, pairs)
	for _, p := range pairs {
		covered[p.f.UUID] = true
	}
	res.Suppressed = len(covered)
	if len(pairs) == 0 {
		return res, nil
	}

	b := &pgx.Batch{}
	for _, p := range pairs {
		b.Queue(`INSERT INTO "SuppressionApplication" (uuid, "orgId", "suppressionUuid", "findingUuid", "scannerRunUuid", "appliedAt", "appliedBy")
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT ("suppressionUuid", "findingUuid") DO UPDATE
			  SET "removedAt" = NULL, "removedReason" = NULL, "appliedAt" = EXCLUDED."appliedAt", "appliedBy" = EXCLUDED."appliedBy"
			  WHERE "SuppressionApplication"."removedAt" IS NOT NULL
			RETURNING uuid`,
			uuid.NewString(), s.OrgID, p.r.Rule.UUID, p.f.UUID, nz(p.f.ScannerRun), now, s.CallSite)
	}
	br := tx.SendBatch(ctx, b)
	for _, p := range pairs {
		var id string
		err := br.QueryRow().Scan(&id)
		if err == pgx.ErrNoRows {
			continue // already live
		}
		if err != nil {
			_ = br.Close()
			return res, fmt.Errorf("upsert application: %w", err)
		}
		res.Applied = append(res.Applied, Application{
			UUID: id, SuppressionUuid: p.r.Rule.UUID, SuppressionType: p.r.Rule.Type, SourceKind: p.r.SourceKind,
			Reason: p.r.Reason, FindingUuid: p.f.UUID, FindingID: p.f.FindingID, Category: p.f.Category,
			Purl: p.f.Purl, PackageName: p.f.PackageName, PackageVersion: p.f.PackageVersion,
			ScannerRunUuid: p.f.ScannerRun, New: true,
		})
	}
	if err := br.Close(); err != nil {
		return res, fmt.Errorf("upsert applications: %w", err)
	}
	if len(res.Applied) == 0 {
		return res, nil
	}

	if err := writeSuppressedTriage(ctx, tx, res.Applied, now); err != nil {
		return res, fmt.Errorf("triage: %w", err)
	}
	actor := actorOf(s.Actor)
	audit := make([]AuditEntry, 0, len(res.Applied))
	for _, a := range res.Applied {
		audit = append(audit, AuditEntry{
			OrgID: s.OrgID, SuppressionUuid: a.SuppressionUuid, Action: "apply",
			ToValue: s.CallSite, FindingUuid: a.FindingUuid,
		})
	}
	if err := writeAudit(ctx, tx, e.Service, actor, audit, now); err != nil {
		return res, fmt.Errorf("audit: %w", err)
	}
	// Minting runs in its own savepoint. A document that cannot be stored (S3
	// down, a role without PutObject) must not take the applications and the
	// Triage with it: those are the decision, the document is its record.
	sp, err := tx.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("mint savepoint: %w", err)
	}
	minted, err := e.mint(ctx, sp, s.OrgID, res.Applied, actor, now)
	if err != nil {
		_ = sp.Rollback(ctx)
		res.MintError = err
		return res, nil
	}
	if err := sp.Commit(ctx); err != nil {
		res.MintError = err
		return res, nil
	}
	res.Minted = minted
	return res, nil
}

// triageFor is the Triage a suppression of this type writes. A won't fix is a
// response, not a justification; a false positive keeps the justification the
// reconcile always wrote, so existing filters read it the same.
func triageFor(suppressionType string) (justification, response string) {
	switch vexrules.KindForSuppressionType(suppressionType) {
	case vexrules.KindFalsePositive:
		return "vulnerable_code_not_present", ""
	case vexrules.KindMitigated:
		return "protected_by_mitigating_control", ""
	default:
		return "", `["will_not_fix"]`
	}
}

// writeSuppressedTriage inserts a Triage "suppressed" row for each finding
// whose latest Triage is not already suppressed.
func writeSuppressedTriage(ctx context.Context, tx pgx.Tx, apps []Application, now int64) error {
	seen := map[string]bool{}
	b := &pgx.Batch{}
	for _, a := range apps {
		if seen[a.FindingUuid] {
			continue
		}
		seen[a.FindingUuid] = true
		just, resp := triageFor(a.SuppressionType)
		detail := "Suppressed by rule " + a.SuppressionUuid
		if a.Reason != "" {
			detail += ": " + a.Reason
		}
		b.Queue(`INSERT INTO "Triage" (uuid, "findingUuid", "createdAt", "lastObserved", seen, "analysisState", "analysisJustification", "analysisResponse", "analysisDetail", "triageAutomated")
			SELECT $1, $2, GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), false, 'suppressed', $4, $5, $6, true
			WHERE COALESCE((SELECT "analysisState" FROM "Triage" WHERE "findingUuid" = $2 ORDER BY "createdAt" DESC LIMIT 1), '') <> 'suppressed'`,
			uuid.NewString(), a.FindingUuid, now, nz(just), nz(resp), detail)
	}
	return tx.SendBatch(ctx, b).Close()
}

func updateSnapshotCount(ctx context.Context, tx pgx.Tx, orgID, scannerRun string) error {
	_, err := tx.Exec(ctx, `UPDATE "IngestionSnapshot" SET suppressed = (
			SELECT count(DISTINCT sa."findingUuid") FROM "SuppressionApplication" sa
			JOIN "Finding" f ON f.uuid = sa."findingUuid"
			WHERE f."scannerRunUuid" = $2 AND sa."orgId" = $1 AND sa."removedAt" IS NULL)
		WHERE "scannerRunUuid" = $2`, orgID, scannerRun)
	return err
}
