package suppression

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	vdbcdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/Vulnetix/vdb-cyclonedx/vexrules"
)

// grounding is the commit and repository a VEX document is about. TEA projects
// an Artifact into a release only for a run with a repository and a commit
// (vdb-site tea_artifacts.go), so that pair is what "grounded" means.
type grounding struct {
	ScannerRun, Repo, Commit string
}

// groundRun returns the run's own grounding, or the latest grounded run for
// the same repository when the run has no CliScanEnvironment (integration
// findings, console edits). ok is false when neither exists.
func groundRun(ctx context.Context, tx pgx.Tx, orgID, scannerRun string) (grounding, bool) {
	if scannerRun == "" {
		return grounding{}, false
	}
	var g grounding
	err := tx.QueryRow(ctx, `SELECT sr.uuid, COALESCE(sr."repoName",''), COALESCE(ce."gitCommit",'')
		FROM "ScannerRun" sr JOIN "CliScanEnvironment" ce ON ce."scannerRunUuid" = sr.uuid
		WHERE sr.uuid = $1 AND sr."orgId" = $2 AND COALESCE(sr."repoName",'') <> '' AND COALESCE(ce."gitCommit",'') <> ''`,
		scannerRun, orgID).Scan(&g.ScannerRun, &g.Repo, &g.Commit)
	if err == nil {
		return g, true
	}
	err = tx.QueryRow(ctx, `SELECT sr2.uuid, sr2."repoName", ce."gitCommit"
		FROM "ScannerRun" sr
		JOIN "ScannerRun" sr2 ON sr2."orgId" = sr."orgId" AND sr2."repoName" = sr."repoName"
		JOIN "CliScanEnvironment" ce ON ce."scannerRunUuid" = sr2.uuid
		WHERE sr.uuid = $1 AND sr."orgId" = $2 AND COALESCE(sr."repoName",'') <> '' AND COALESCE(ce."gitCommit",'') <> ''
		ORDER BY sr2."createdAt" DESC LIMIT 1`,
		scannerRun, orgID).Scan(&g.ScannerRun, &g.Repo, &g.Commit)
	return g, err == nil
}

// mint writes one CycloneDX VEX per (scanner run, rule) for the new
// applications. Each statement carries the marker of the rule it came from, so
// the document links back to that rule when it is ingested again.
func (e *Engine) mint(ctx context.Context, tx pgx.Tx, orgID string, apps []Application, actor actorColumns, now int64) ([]MintedVEX, error) {
	type key struct{ run, rule string }
	groups := map[key][]Application{}
	var keys []key
	for _, a := range apps {
		k := key{a.ScannerRunUuid, a.SuppressionUuid}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], a)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].run != keys[j].run {
			return keys[i].run < keys[j].run
		}
		return keys[i].rule < keys[j].rule
	})

	var out []MintedVEX
	for _, k := range keys {
		group := groups[k]
		first := group[0]
		marker := vexrules.Marker{Type: first.SuppressionType, UUID: first.SuppressionUuid, Source: first.SourceKind}
		enc := vexrules.EncodeSuppression(marker, first.Reason)
		findings := make([]vdbcdx.VEXFinding, 0, len(group))
		for _, a := range group {
			eco, name, version := vdbcdx.ParsePurl(a.Purl)
			if name == "" {
				name, version = a.PackageName, a.PackageVersion
			}
			findings = append(findings, vdbcdx.VEXFinding{
				CVEID:         a.FindingID,
				Package:       name,
				Ecosystem:     eco,
				InstalledVer:  version,
				Status:        enc.CDXState,
				Justification: enc.CDXJustification,
				Responses:     enc.CDXResponses,
				Detail:        a.Reason,
				Properties:    marker.Properties(),
			})
		}

		g, grounded := groundRun(ctx, tx, orgID, k.run)
		var project *vdbcdx.AIBOMProject
		if grounded {
			project = &vdbcdx.AIBOMProject{Name: g.Repo, Version: g.Commit, Commit: g.Commit}
		}
		doc, err := vdbcdx.BuildCDXVEX(findings, vdbcdx.VEXOptions{
			ToolName:    "vulnetix-suppression",
			GeneratedAt: time.Unix(now, 0).UTC().Format(time.RFC3339),
			AuthorName:  firstNonEmpty(actor.Label, actor.ID, "Vulnesis"),
			Project:     project,
		})
		if err != nil {
			return out, fmt.Errorf("build VEX for rule %s: %w", k.rule, err)
		}

		m := MintedVEX{OpenVexUuid: uuid.NewString(), Grounded: grounded}
		if grounded {
			m.ScannerRunUuid, m.Repository, m.GitCommit = g.ScannerRun, g.Repo, g.Commit
		}
		docID := "urn:vulnetix:suppression:" + k.rule + ":" + m.OpenVexUuid

		if e.Putter != nil {
			s3key := fmt.Sprintf("%s/vex/suppression-%s.cdx.json", orgID, m.OpenVexUuid)
			sum := sha256.Sum256(doc)
			hash := hex.EncodeToString(sum[:])
			if err := e.Putter.PutWithMetadata(ctx, s3key, doc, "application/vnd.cyclonedx+json", map[string]string{
				"orgUuid": orgID, "sha256": hash, "uploadedAt": fmt.Sprint(now),
				"originalFileName": "suppression-" + m.OpenVexUuid + ".cdx.json",
			}); err != nil {
				return out, fmt.Errorf("store VEX: %w", err)
			}
			meta, _ := json.Marshal(map[string]any{
				"source": "suppression-engine", "suppressionUuid": k.rule, "grounded": grounded,
				"actorKind": actor.Kind, "actorLabel": firstNonEmpty(actor.Label, actor.ID),
			})
			m.ArtifactUuid = uuid.NewString()
			if _, err := tx.Exec(ctx, `INSERT INTO "Artifact" (uuid, type, date, "bomFormat", "r2Bucket", "r2Key", "fileSize", "contentType",
					checksum, "uploadSource", "uploadMethod", "uploadedAt", "accessCount", "scannerRunUuid", "customMetadata")
				VALUES ($1, 'vex', $2, 'CycloneDX', $3, $4, $5, 'application/vnd.cyclonedx+json', $6, 'vulnetix', 'suppression-engine', $2, 0, $7, $8)`,
				m.ArtifactUuid, now, nz(e.Bucket), s3key, len(doc), hash, nz(m.ScannerRunUuid), string(meta)); err != nil {
				return out, fmt.Errorf("insert artifact: %w", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO "Link" (url, "contentType", "artifactUuid") VALUES ($1, 'PLAIN_JSON', $2)`,
				"/"+s3key, m.ArtifactUuid); err != nil {
				return out, fmt.Errorf("insert link: %w", err)
			}
		} else {
			m.Grounded = false
		}

		if _, err := tx.Exec(ctx, `INSERT INTO "OpenVex" (uuid, "orgId", context, "documentId", author, "authorRole", timestamp, "lastUpdated",
				version, tooling, "documentJSON", "createdAt", "sourceFormat", "artifactUuid", "scannerRunUuid", "gitCommit",
				"repositoryFullName", grounded, "mintedBySuppressionUuid", "ingestedAt",
				"actorKind", "actorId", "actorLabel", "actorEmail", "actorVerified", "provenanceJSON")
			VALUES ($1, $2, 'https://cyclonedx.org/schema/bom-1.6.schema.json', $3, $4, 'tool', $5, $5, 1, 'vulnetix-suppression', $6, $5,
				'cyclonedx', $7, $8, $9, $10, $11, $12, $5, $13, $14, $15, $16, $17, $18)`,
			m.OpenVexUuid, orgID, docID, firstNonEmpty(actor.Label, actor.ID, "Vulnesis"), now, string(doc),
			nz(m.ArtifactUuid), nz(m.ScannerRunUuid), nz(m.GitCommit), nz(m.Repository), m.Grounded, k.rule,
			nz(actor.Kind), nz(actor.ID), nz(actor.Label), nz(actor.Email), actor.Verified, nz(actor.JSON)); err != nil {
			return out, fmt.Errorf("insert OpenVex: %w", err)
		}
		ids := make([]string, 0, len(group))
		for _, a := range group {
			ids = append(ids, a.UUID)
		}
		if _, err := tx.Exec(ctx, `UPDATE "SuppressionApplication" SET "vexOpenVexUuid" = $1, "vexArtifactUuid" = $2, grounded = $3, "gitCommit" = $4
			WHERE uuid = ANY($5)`, m.OpenVexUuid, nz(m.ArtifactUuid), m.Grounded, nz(m.GitCommit), ids); err != nil {
			return out, fmt.Errorf("link applications: %w", err)
		}
		if err := writeAudit(ctx, tx, e.Service, actor, []AuditEntry{{
			OrgID: orgID, SuppressionUuid: k.rule, Action: "mint_vex", OpenVexUuid: m.OpenVexUuid,
			ToValue: groundedWord(m), FromValue: fmt.Sprintf("%d findings", len(group)),
		}}, now); err != nil {
			return out, err
		}
		out = append(out, m)
	}
	return out, nil
}

func groundedWord(m MintedVEX) string {
	if m.Grounded {
		return "grounded " + m.Repository + "@" + m.GitCommit
	}
	return "not tied to a commit"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
