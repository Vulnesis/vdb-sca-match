package suppression

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Vulnesis/vdb-cyclonedx/vexrules"
)

// maxDocumentJSON caps the copy of a document kept in OpenVex.documentJSON.
// The file itself is in S3 when the caller stored it.
const maxDocumentJSON = 4 << 20

// IngestInput is one VEX document arriving from any source.
type IngestInput struct {
	OrgID string
	Data  []byte
	// Origin says how it arrived: scan_vex_file, bom_enrich, upload,
	// bom_analysis, triage, reconcile, defend, jail, console.
	Origin string
	// ScannerRunUuid grounds the document when the run has a commit.
	ScannerRunUuid string
	// Repository scopes the rules the document creates. Empty means org-wide
	// (limited to each statement's vulnerability and product).
	Repository string
	GitCommit  string
	// ArtifactUuid is the stored file, when the caller kept one.
	ArtifactUuid string
	Actor        vexrules.Identity
	// DeferFindingWork leaves everything that touches the org's existing
	// findings to the caller: ending a superseded rule's applications,
	// writing a statement's Triage evidence and applying the new rules.
	// Ingest then writes only the document, its statements and the rule rows,
	// which is bounded by the size of the document, and returns the rest in
	// IngestResult.FollowUps for RunFollowUps. A request that must answer
	// quickly sets it. The rules are in force for every later scan as soon as
	// Ingest commits; only the backfill onto older rows waits.
	DeferFindingWork bool
}

// IngestResult is what an ingest did.
type IngestResult struct {
	OpenVexUuid string
	Format      vexrules.Format
	Grounded    bool
	Statements  int
	// Created are the rules written. Pending ones wait for review.
	Created []string
	Pending []string
	// Linked are statements that named one of the org's own rules.
	Linked []string
	// Superseded are VEX rules a newer statement replaced.
	Superseded []string
	// Triaged counts findings whose Triage took a VEX state as evidence.
	Triaged int
	// Applied counts findings the new rules now cover.
	Applied int
	// FollowUps is the finding work left for RunFollowUps, in the order it
	// would otherwise have run. Empty unless IngestInput.DeferFindingWork.
	FollowUps []FollowUp
}

// Ingest parses a VEX document, classifies every statement and acts on it:
// a false positive or won't fix becomes a rule (active, or pending review when
// only prose said so), a statement carrying one of the org's own markers links
// to that rule, a newer statement replaces an older VEX rule for the same
// vulnerability, product and repository, and every other decision is written
// to Triage as evidence. VEX never changes a rule a person made in the
// console or the CLI.
func (e *Engine) Ingest(ctx context.Context, db Beginner, in IngestInput) (IngestResult, error) {
	doc, err := vexrules.Parse(in.Data)
	if err != nil {
		return IngestResult{}, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return IngestResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := e.now()
	actor := actorOf(in.Actor)
	res := IngestResult{Format: doc.Format, Statements: len(doc.Statements)}

	g, grounded := groundRun(ctx, tx, in.OrgID, in.ScannerRunUuid)
	repo := in.Repository
	commit := in.GitCommit
	if grounded {
		res.Grounded = true
		if repo == "" {
			repo = g.Repo
		}
		if commit == "" {
			commit = g.Commit
		}
	}

	docJSON := string(in.Data)
	if len(docJSON) > maxDocumentJSON {
		docJSON = ""
	}
	res.OpenVexUuid = uuid.NewString()
	docTS := now
	if !doc.Timestamp.IsZero() {
		docTS = doc.Timestamp.Unix()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO "OpenVex" (uuid, "orgId", context, "documentId", author, "authorRole", timestamp, "lastUpdated",
			version, tooling, "documentJSON", "createdAt", "sourceFormat", "artifactUuid", "scannerRunUuid", "gitCommit",
			"repositoryFullName", grounded, "ingestedAt", "actorKind", "actorId", "actorLabel", "actorEmail", "actorVerified", "provenanceJSON")
		VALUES ($1, $2, $3, $4, $5, 'author', $6, $6, 1, $7, $8, $9, $10, $11, $12, $13, $14, $15, $9, $16, $17, $18, $19, $20, $21)`,
		res.OpenVexUuid, in.OrgID, string(doc.Format), firstNonEmpty(doc.ID, "urn:vulnetix:ingest:"+res.OpenVexUuid),
		firstNonEmpty(doc.Author, "unknown"), docTS, "ingest:"+firstNonEmpty(in.Origin, "unknown"), docJSON, now,
		string(doc.Format), nz(in.ArtifactUuid), nz(ifGrounded(grounded, g.ScannerRun)), nz(commit), nz(repo), grounded,
		nz(actor.Kind), nz(actor.ID), nz(actor.Label), nz(actor.Email), actor.Verified, nz(actor.JSON)); err != nil {
		return res, fmt.Errorf("insert OpenVex: %w", err)
	}

	// The Member lookup is a convenience; a failed query must not abort the
	// ingest, so it runs in a savepoint that is always rolled back.
	member := ""
	if sp, err := tx.Begin(ctx); err == nil {
		member = MemberForEmail(ctx, sp, in.OrgID, actor.Email)
		_ = sp.Rollback(ctx)
	}
	var audit []AuditEntry
	var toApply []string

	for _, s := range doc.Statements {
		d := vexrules.Classify(s)
		raw, _ := json.Marshal(s.Raw)
		products, _ := json.Marshal(s.Products)
		aliases, _ := json.Marshal(s.Aliases)
		stTS := docTS
		if !s.Timestamp.IsZero() {
			stTS = s.Timestamp.Unix()
		}
		linked := ""
		if d.Marker != nil {
			var owned bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM "Suppression" WHERE uuid = $1 AND "orgId" = $2)`, d.Marker.UUID, in.OrgID).Scan(&owned)
			if owned {
				linked = d.Marker.UUID
			} else {
				// Another org's marker carries no authority here. Read the
				// fields as any third-party statement.
				s.Raw.CDXProperties, s.Raw.OpenVEXStatusNotes, s.Raw.CSAFNotes = nil, "", nil
				d = vexrules.Classify(s)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO "OpenVexStatement" (uuid, "openVexUuid", "statementId", timestamp, "vulnerabilityId",
				"vulnerabilityName", "vulnerabilityAliases", "productsJSON", status, "statusNotes", justification, "impactStatement",
				"actionStatement", "dispositionKind", "dispositionBasis", "rawDispositionJSON", "suppressionUuid")
			VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			uuid.NewString(), res.OpenVexUuid, nz(s.Ref), stTS, s.VulnID, string(aliases), string(products),
			firstNonEmpty(string(s.Status), "under_investigation"), nz(clip(d.Reason, 1000)), nz(s.Justification),
			nz(clip(s.ImpactStatement, 4000)), nz(clip(s.ActionStatement, 4000)), string(d.Kind), nz(string(d.Basis)), string(raw), nz(linked)); err != nil {
			return res, fmt.Errorf("insert statement: %w", err)
		}
		if s.VulnID == "" {
			continue
		}
		if linked != "" {
			res.Linked = append(res.Linked, linked)
			audit = append(audit, AuditEntry{OrgID: in.OrgID, SuppressionUuid: linked, Action: "link", OpenVexUuid: res.OpenVexUuid, ToValue: s.Ref})
			continue
		}

		rules := vexrules.StatementRules(s, d, repo)
		if !d.Rule {
			// A newer non-rule statement withdraws an older VEX rule for the
			// same key: the publisher changed their mind.
			for _, k := range statementKeys(s, repo) {
				ids, err := supersedeOlder(ctx, tx, in.OrgID, s.VulnID, k, repo, stTS, "", now)
				if err != nil {
					return res, err
				}
				for _, id := range ids {
					res.Superseded = append(res.Superseded, id)
					audit = append(audit, AuditEntry{OrgID: in.OrgID, SuppressionUuid: id, Action: "supersede",
						Reason:      "Superseded by " + firstNonEmpty(doc.ID, res.OpenVexUuid) + " statement " + s.Ref + " (" + string(d.Kind) + ")",
						OpenVexUuid: res.OpenVexUuid})
					// Withdraw before writing the new evidence, so the
					// statement's own state is the finding's latest Triage.
					if err := e.step(ctx, tx, in, &res, FollowUp{Kind: FollowUpRemove, OrgID: in.OrgID, RuleUuid: id}); err != nil {
						return res, err
					}
				}
			}
			if d.Kind == vexrules.KindTriageOnly {
				if err := e.step(ctx, tx, in, &res, FollowUp{Kind: FollowUpEvidence, OrgID: in.OrgID, Statement: s,
					Repo: repo, DocID: firstNonEmpty(doc.ID, res.OpenVexUuid)}); err != nil {
					return res, err
				}
			}
			continue
		}

		for _, r := range rules {
			var newer bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM "Suppression"
					WHERE "orgId" = $1 AND "sourceKind" = 'vex' AND lower("vulnerabilityId") = lower($2)
					  AND COALESCE("productPurlBase",'') = $3 AND COALESCE("repositoryFullName",'') = $4
					  AND COALESCE("statementTimestamp",0) >= $5 AND ("isActive" OR "reviewState" = 'pending'))`,
				in.OrgID, s.VulnID, r.ProductPurlBase, repo, stTS).Scan(&newer); err != nil {
				return res, err
			}
			if newer {
				continue // an equal or newer statement already holds this key
			}
			id := uuid.NewString()
			ids, err := supersedeOlder(ctx, tx, in.OrgID, s.VulnID, r.ProductPurlBase, repo, stTS, id, now)
			if err != nil {
				return res, err
			}
			for _, old := range ids {
				res.Superseded = append(res.Superseded, old)
				audit = append(audit, AuditEntry{OrgID: in.OrgID, SuppressionUuid: old, Action: "supersede",
					Reason: "Superseded by " + firstNonEmpty(doc.ID, res.OpenVexUuid) + " statement " + s.Ref, ToValue: id,
					OpenVexUuid: res.OpenVexUuid})
				if err := e.step(ctx, tx, in, &res, FollowUp{Kind: FollowUpRemove, OrgID: in.OrgID, RuleUuid: old}); err != nil {
					return res, err
				}
			}
			reviewState := any(nil)
			if !d.Active {
				reviewState = "pending"
			}
			reason := d.Reason
			if doc.Author != "" {
				reason += " (" + doc.Author + ")"
			}
			if detail := firstNonEmpty(s.ActionStatement, s.ImpactStatement); detail != "" {
				reason += ": " + detail
			}
			productPurl := ""
			for _, p := range s.Products {
				if vexrules.PurlBase(p.Purl) == r.ProductPurlBase {
					productPurl = p.Purl
					break
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO "Suppression" (uuid, "orgId", "suppressionType", reason, "createdAt", "createdBy",
					"repositoryFullName", origin, "updatedAt", "isActive", "vulnerabilityId", "productPurl", "productPurlBase",
					"sourceKind", "matchBasis", "sourceOpenVexUuid", "sourceArtifactUuid", "sourceDocumentId", "sourceStatementRef",
					"statementTimestamp", "scannerRunUuid", "gitCommit", "reviewState",
					"actorKind", "actorId", "actorLabel", "actorEmail", "actorVerified", "provenanceJSON")
				VALUES ($1, $2, $3, $4, $5, $6, $7, 'vex', $5, $8, $9, $10, $11, 'vex', $12, $13, $14, $15, $16, $17, $18, $19, $20,
					$21, $22, $23, $24, $25, $26)`,
				id, in.OrgID, r.Type, clip(reason, 2000), now, nz(member), nz(repo), r.IsActive, s.VulnID, nz(productPurl),
				nz(r.ProductPurlBase), string(d.Basis), res.OpenVexUuid, nz(in.ArtifactUuid), nz(doc.ID), nz(s.Ref), stTS,
				nz(ifGrounded(grounded, g.ScannerRun)), nz(commit), reviewState,
				nz(actor.Kind), nz(actor.ID), nz(actor.Label), nz(actor.Email), actor.Verified, nz(actor.JSON)); err != nil {
				return res, fmt.Errorf("insert rule: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE "OpenVexStatement" SET "suppressionUuid" = $1
				WHERE "openVexUuid" = $2 AND "statementId" IS NOT DISTINCT FROM $3 AND "suppressionUuid" IS NULL`,
				id, res.OpenVexUuid, nz(s.Ref)); err != nil {
				return res, err
			}
			audit = append(audit, AuditEntry{OrgID: in.OrgID, SuppressionUuid: id, Action: "create",
				ToValue: r.Type + " from " + string(doc.Format) + " (" + string(d.Basis) + ")", Reason: d.Reason, OpenVexUuid: res.OpenVexUuid})
			if r.IsActive {
				res.Created = append(res.Created, id)
				toApply = append(toApply, id)
			} else {
				res.Pending = append(res.Pending, id)
			}
		}
	}

	if err := writeAudit(ctx, tx, e.Service, actor, audit, now); err != nil {
		return res, err
	}
	for _, id := range toApply {
		if err := e.step(ctx, tx, in, &res, FollowUp{Kind: FollowUpApply, OrgID: in.OrgID, RuleUuid: id}); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

// step runs one piece of finding work inside the ingest's transaction, or
// queues it when the caller asked to run it later.
func (e *Engine) step(ctx context.Context, tx pgx.Tx, in IngestInput, res *IngestResult, f FollowUp) error {
	if in.DeferFindingWork {
		res.FollowUps = append(res.FollowUps, f)
		return nil
	}
	out, err := e.runFollowUp(ctx, tx, f, in.Actor)
	res.Triaged += out.Triaged
	res.Applied += out.Applied
	return err
}

func ifGrounded(ok bool, v string) string {
	if ok {
		return v
	}
	return ""
}

func statementKeys(s vexrules.Statement, repo string) []string {
	d := vexrules.Disposition{Rule: true, Active: true}
	var out []string
	for _, r := range vexrules.StatementRules(s, d, repo) {
		out = append(out, r.ProductPurlBase)
	}
	return out
}

// supersedeOlder deactivates VEX rules for the same key whose statement is
// older than ts. Rules made from one of the org's own markers are a person's
// decision and are left alone, as is every non-VEX rule.
func supersedeOlder(ctx context.Context, tx pgx.Tx, orgID, vulnID, purlBase, repo string, ts int64, by string, now int64) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE "Suppression" SET "isActive" = false, "deactivatedAt" = $6, "deactivatedReason" = 'Superseded by a newer VEX statement',
			"supersededBy" = $7, "updatedAt" = $6, "reviewState" = CASE WHEN "reviewState" = 'pending' THEN 'rejected' ELSE "reviewState" END
		WHERE "orgId" = $1 AND "sourceKind" = 'vex' AND COALESCE("matchBasis",'') <> 'marker'
		  AND lower("vulnerabilityId") = lower($2) AND COALESCE("productPurlBase",'') = $3 AND COALESCE("repositoryFullName",'') = $4
		  AND COALESCE("statementTimestamp",0) < $5 AND ("isActive" OR "reviewState" = 'pending')
		RETURNING uuid`, orgID, vulnID, purlBase, repo, ts, now, nz(by))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// triageStateFor maps a non-rule VEX statement onto the Triage state the
// console already shows.
func triageStateFor(s vexrules.Statement) (state, justification, response string) {
	switch s.Status {
	case vexrules.StatusNotAffected:
		return "not_affected", firstNonEmpty(s.Justification, s.Raw.CDXJustification), ""
	case vexrules.StatusFixed:
		return "resolved", "", ""
	case vexrules.StatusAffected:
		if len(s.Raw.CDXResponses) > 0 {
			b, _ := json.Marshal(s.Raw.CDXResponses)
			response = string(b)
		}
		return "exploitable", "", response
	}
	return "", "", ""
}

// evidenceFindingsSQL selects the findings a triage-only statement names. It is
// served by Finding_orgId_lowerFindingId_createdAt_idx; without that index it
// reads every Finding row the org has.
const evidenceFindingsSQL = `SELECT ` + findingCols + ` FROM "Finding" f
		WHERE f."orgId" = $1 AND lower(f."findingId") = ANY($2)
		ORDER BY f."createdAt" DESC LIMIT $3`

// writeEvidenceTriage records a triage-only statement on the matching findings
// whose latest Triage is still automated or untriaged. A person's triage is
// never overwritten by a document.
func writeEvidenceTriage(ctx context.Context, tx pgx.Tx, orgID string, s vexrules.Statement, repo, docID string, now int64) (int, error) {
	state, just, resp := triageStateFor(s)
	if state == "" {
		return 0, nil
	}
	ids := []string{strings.ToLower(s.VulnID)}
	for _, a := range s.Aliases {
		ids = append(ids, strings.ToLower(a))
	}
	rows, err := tx.Query(ctx, evidenceFindingsSQL, orgID, ids, maxRuleChangeFindings)
	if err != nil {
		return 0, err
	}
	findings, err := scanFindings(rows)
	if err != nil {
		return 0, err
	}
	rules := vexrules.StatementRules(s, vexrules.Disposition{Rule: true, Active: true}, repo)
	b := &pgx.Batch{}
	n := 0
	for _, f := range findings {
		m := f.toMatch()
		hit := false
		for _, r := range rules {
			if vexrules.RuleMatches(r, m) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		n++
		detail := clip("From VEX "+docID+": "+firstNonEmpty(s.ImpactStatement, s.ActionStatement, string(s.Status)), 2000)
		b.Queue(`INSERT INTO "Triage" (uuid, "findingUuid", "createdAt", "lastObserved", seen, "analysisState", "analysisJustification", "analysisResponse", "analysisDetail", "triageAutomated")
			SELECT $1, $2, GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), GREATEST($3::bigint, COALESCE((SELECT max("createdAt") FROM "Triage" WHERE "findingUuid" = $2), 0) + 1), false, $4, $5, $6, $7, true
			WHERE NOT EXISTS (SELECT 1 FROM (SELECT "analysisState", "triageAutomated", "memberUuid" FROM "Triage" WHERE "findingUuid" = $2 ORDER BY "createdAt" DESC LIMIT 1) t
			                  WHERE t."memberUuid" IS NOT NULL OR t."analysisState" IN ('suppressed', $4)
			                     OR (NOT t."triageAutomated" AND t."analysisState" NOT IN ('in_triage', 'under_investigation')))`,
			uuid.NewString(), f.UUID, now, state, nz(just), nz(resp), detail)
	}
	if n == 0 {
		return 0, nil
	}
	return n, tx.SendBatch(ctx, b).Close()
}
