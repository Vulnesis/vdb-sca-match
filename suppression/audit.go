package suppression

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Vulnesis/vdb-cyclonedx/vexrules"
)

// AuditEntry is one SuppressionAudit row. The actor is supplied by the caller
// of WriteAudit.
type AuditEntry struct {
	OrgID           string
	SuppressionUuid string
	// Action is one of create, update, extend, review, approve, reject,
	// activate, deactivate, supersede, delete, apply, unapply, link, mint_vex.
	Action      string
	FromValue   string
	ToValue     string
	Reason      string
	FindingUuid string
	OpenVexUuid string
}

// WriteAudit appends audit rows. Services call it for the rule changes they
// make themselves (create, extend, review, deactivate, delete); the engine
// writes apply, unapply, link, supersede and mint_vex.
func (e *Engine) WriteAudit(ctx context.Context, db Beginner, actor vexrules.Identity, entries ...AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := writeAudit(ctx, tx, e.Service, actorOf(actor), entries, e.now()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func writeAudit(ctx context.Context, tx pgx.Tx, service string, a actorColumns, entries []AuditEntry, now int64) error {
	b := &pgx.Batch{}
	for _, en := range entries {
		b.Queue(`INSERT INTO "SuppressionAudit" ("orgId", "suppressionUuid", action, "fromValue", "toValue", reason,
				"actorKind", "actorId", "actorLabel", "actorVerified", "evidenceJSON", service, "findingUuid", "openVexUuid", "createdAt")
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			en.OrgID, en.SuppressionUuid, en.Action, nz(en.FromValue), nz(en.ToValue), nz(clip(en.Reason, 2000)),
			nz(a.Kind), nz(a.ID), nz(a.Label), a.Verified, nz(a.JSON), service, nz(en.FindingUuid), nz(en.OpenVexUuid), now)
	}
	return tx.SendBatch(ctx, b).Close()
}

// ActorColumns returns the values a service writes to a Suppression row's
// actor* columns and provenanceJSON for the given identity.
func ActorColumns(id vexrules.Identity) (kind, actorID, label, email string, verified bool, provenanceJSON string) {
	a := actorOf(id)
	return a.Kind, a.ID, a.Label, a.Email, a.Verified, a.JSON
}

// MemberForEmail resolves an email to a saas Member uuid in the org, for
// Suppression.createdBy. It returns "" when there is no such member; the email
// is a claim unless a verified rung carried it, and the actor columns say so.
func MemberForEmail(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, orgID, email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}
	var id string
	if err := q.QueryRow(ctx, `SELECT uuid FROM "Member" WHERE lower(email) = $1 AND "orgId" = $2 LIMIT 1`, email, orgID).Scan(&id); err != nil {
		return ""
	}
	return id
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
