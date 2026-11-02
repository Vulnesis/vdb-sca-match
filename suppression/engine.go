// Package suppression applies suppression rules to findings, records each
// application, writes the Triage state that follows, and mints a VEX document
// for what it suppressed.
//
// Every service that writes a Finding calls Apply in the same transaction:
// vdb-api for cli.* ingestion, vdb-site for integrations and uploads, the
// CycloneDX upload processor and the SCA monitor. That is the only way a rule
// keeps covering the rows each new scan writes; before this, a rule was bound
// to one Finding row and the next scan's rows escaped it.
//
// Rule matching is vexrules.RuleMatches (vdb-cyclonedx), the same code the CLI
// uses locally, plus an exact match on Suppression.findingUuid. The decision
// to suppress is recorded as a SuppressionApplication row; the read paths
// follow it. History goes to the append-only SuppressionAudit table.
//
// Everything runs inside a savepoint taken from the caller's transaction, so a
// failure here never aborts the ingest that called it. Callers log the error
// and carry on: a finding left unsuppressed is visible and fixable, a lost
// ingest is not.
package suppression

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// Beginner is a pgx pool or transaction. Begin on a transaction opens a
// savepoint, which is what the engine wants.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Putter stores a minted VEX document. Every service already has an S3 adapter
// with this method.
type Putter interface {
	PutWithMetadata(ctx context.Context, key string, data []byte, contentType string, metadata map[string]string) error
}

// Engine holds what minting needs. A nil Putter still records applications
// and Triage; the minted document is then kept in the OpenVex row only and is
// never grounded, because TEA can only serve a stored file.
type Engine struct {
	Putter Putter
	Bucket string
	// Service names the caller in audit rows: vdb-api, vdb-site, uploads,
	// sca-monitor.
	Service string
	// Now returns unix seconds. Tests replace it.
	Now func() int64
	// Conditions evaluates the when (CEL) of rules that carry one
	// (Suppression.expr). Such a rule covers a finding only when its anchors
	// match AND the evaluator says the expression holds. With no evaluator it
	// covers nothing: applying it on its anchors alone would suppress more
	// than its author declared, and an unsuppressed finding is visible and
	// fixable where a wrongly suppressed one is not.
	Conditions ConditionEvaluator
}

// ConditionEvaluator decides a rule's when expression for findings. The
// finding facts an expression reads (scores, KEV, reachability, exposure) are
// the service's own read model, which is why the engine asks rather than
// computes them.
type ConditionEvaluator interface {
	// Holds returns the subset of findingUuids (Finding.uuid, all in orgID)
	// for which expr evaluates true. It runs inside the engine's savepoint.
	Holds(ctx context.Context, tx pgx.Tx, orgID, expr string, findingUuids []string) (map[string]bool, error)
}

func (e *Engine) now() int64 {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().Unix()
}

// Scope is the set of findings an Apply call covers.
type Scope struct {
	// OrgID is the saas Org uuid (Finding.orgId).
	OrgID string
	// ScannerRunUuid limits the scope to one run's findings when FindingUuids
	// is empty, and keys the IngestionSnapshot.suppressed count.
	ScannerRunUuid string
	// FindingUuids, when set, is the exact scope.
	FindingUuids []string
	// CallSite is recorded on each application: cli-sca, cli-sarif, cli-eol,
	// cli-binary, cloud-native, cloud-waf, github-alerts, wiz, uploads,
	// sca-monitor, cli-local, rule-change.
	CallSite string
	// Actor is who caused the write. For an ingest it is whoever ran the
	// scan; for a rule change, whoever changed the rule.
	Actor vexrules.Identity
}

// Application is one rule covering one finding.
type Application struct {
	UUID            string
	SuppressionUuid string
	SuppressionType string
	SourceKind      string
	Reason          string
	FindingUuid     string
	FindingID       string
	Category        string
	Purl            string
	PackageName     string
	PackageVersion  string
	ScannerRunUuid  string
	// New is false when the application already existed and was live.
	New bool
}

// Result is what an Apply call did.
type Result struct {
	// Applied are the applications written or revived by this call.
	Applied []Application
	// Suppressed is how many findings in scope are covered by a live rule
	// after the call.
	Suppressed int
	// Minted are the VEX documents written for the new applications.
	Minted []MintedVEX
	// MintError is set when the applications were recorded but their VEX
	// could not be written. Callers log it; nothing else is lost.
	MintError error
	// ConditionError is set when a rule's when expression could not be
	// evaluated. That rule covered nothing in this call; every other rule
	// applied as usual. Callers log it.
	ConditionError error
}

// MintedVEX is one VEX document the engine wrote.
type MintedVEX struct {
	OpenVexUuid    string
	ArtifactUuid   string
	ScannerRunUuid string
	GitCommit      string
	Repository     string
	Grounded       bool
}

// actorColumns is the primary rung flattened for the actor* columns.
type actorColumns struct {
	Kind, ID, Label, Email string
	Verified               bool
	JSON                   string
}

func actorOf(id vexrules.Identity) actorColumns {
	p := id.Primary
	if p.Kind == "" {
		p = vexrules.Evidence{Kind: vexrules.EvidenceSystem, ID: "vulnetix"}
	}
	b, _ := json.Marshal(id)
	return actorColumns{Kind: string(p.Kind), ID: p.ID, Label: p.Label, Email: id.Email(), Verified: p.Verified, JSON: string(b)}
}

// SystemActor is the identity for work no person asked for (a scheduled
// sweep).
func SystemActor(label string) vexrules.Identity {
	return vexrules.NewIdentity(vexrules.Evidence{Kind: vexrules.EvidenceSystem, ID: "vulnetix", Label: label})
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}
