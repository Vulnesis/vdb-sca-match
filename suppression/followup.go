package suppression

import (
	"context"
	"fmt"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// FollowUpKind is one kind of finding work an ingest can leave for later.
type FollowUpKind string

const (
	// FollowUpRemove ends the live applications of a rule a newer VEX
	// statement superseded and returns its findings to in_triage.
	FollowUpRemove FollowUpKind = "remove"
	// FollowUpEvidence writes a triage-only statement's state to the Triage
	// of the findings it names.
	FollowUpEvidence FollowUpKind = "evidence"
	// FollowUpApply applies a newly created rule to the org's findings.
	FollowUpApply FollowUpKind = "apply"
)

// supersededReason is why a superseded rule's applications end.
const supersededReason = "superseded by a newer VEX statement"

// FollowUp is one piece of finding work Ingest left for RunFollowUps. Each one
// can read and write thousands of Finding, Triage and SuppressionApplication
// rows (and an apply mints a VEX per scanner run), which is why a caller
// answering a request runs them after it has answered.
type FollowUp struct {
	Kind  FollowUpKind
	OrgID string
	// RuleUuid is the Suppression a remove or an apply acts on.
	RuleUuid string
	// Statement, Repo and DocID are what an evidence step writes.
	Statement vexrules.Statement
	Repo      string
	DocID     string
}

// FollowUpResult is what RunFollowUps did.
type FollowUpResult struct {
	// Removed counts findings whose application of a superseded rule ended.
	Removed int
	// Triaged counts findings whose Triage took a VEX state as evidence.
	Triaged int
	// Applied counts findings the new rules now cover.
	Applied int
	// Errors holds one error per step that failed. A failed step does not
	// stop the steps after it.
	Errors []error
}

// RunFollowUps runs the work an ingest with DeferFindingWork returned, in
// order, each step in its own transaction on db (a pool), so one large step
// neither holds the others' locks nor costs them their work. A step that
// fails is reported and skipped; the scan after it, or the
// suppression-apply-sweep, covers what it missed.
func (e *Engine) RunFollowUps(ctx context.Context, db Beginner, work []FollowUp, actor vexrules.Identity) FollowUpResult {
	var res FollowUpResult
	for _, f := range work {
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s %s: %w", f.Kind, f.RuleUuid, err))
			continue
		}
		out, err := e.runFollowUp(ctx, db, f, actor)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("%s %s: %w", f.Kind, firstNonEmpty(f.RuleUuid, f.Statement.VulnID), err))
			continue
		}
		res.Removed += out.Removed
		res.Triaged += out.Triaged
		res.Applied += out.Applied
	}
	return res
}

// runFollowUp runs one step on db, which is the ingest's own transaction when
// the work is not deferred and a pool when it is.
func (e *Engine) runFollowUp(ctx context.Context, db Beginner, f FollowUp, actor vexrules.Identity) (FollowUpResult, error) {
	var out FollowUpResult
	switch f.Kind {
	case FollowUpRemove:
		n, err := e.Remove(ctx, db, f.OrgID, f.RuleUuid, supersededReason, actor)
		out.Removed = n
		return out, err
	case FollowUpApply:
		r, err := e.ApplyRule(ctx, db, f.OrgID, f.RuleUuid, actor)
		out.Applied = len(r.Applied)
		return out, err
	case FollowUpEvidence:
		tx, err := db.Begin(ctx)
		if err != nil {
			return out, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		n, err := writeEvidenceTriage(ctx, tx, f.OrgID, f.Statement, f.Repo, f.DocID, e.now())
		if err != nil {
			return out, err
		}
		out.Triaged = n
		return out, tx.Commit(ctx)
	}
	return out, fmt.Errorf("unknown follow-up kind %q", f.Kind)
}
