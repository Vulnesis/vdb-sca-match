package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// vulnetixFingerprintKey is the key the Vulnetix SARIF writer uses, so a
// round-trip through this package preserves the CLI's own fingerprints.
const vulnetixFingerprintKey = "vulnetix/v1"

// githubPartialFingerprintKey is the key GitHub code scanning and several
// third-party tools populate.
const githubPartialFingerprintKey = "primaryLocationLineHash/v1"

// fingerprintOf picks the most stable identifier available for a result.
//
// Precedence: the Vulnetix key, then any declared fingerprint, then GitHub's
// partial fingerprint, then any partial fingerprint, then the result's guid or
// correlation guid, and finally a synthesized digest.
//
// Maps are iterated in sorted key order, never Go's randomized order: the value
// this returns becomes SarifResults.guid, which is upserted ON CONFLICT, so a
// non-deterministic choice would create duplicate rows every time a publish job
// re-runs.
func fingerprintOf(res *Result, toolName, uri string) string {
	if res == nil {
		return ""
	}
	if v := strings.TrimSpace(res.Fingerprints[vulnetixFingerprintKey]); v != "" {
		return v
	}
	if v := firstBySortedKey(res.Fingerprints); v != "" {
		return v
	}
	if v := strings.TrimSpace(res.PartialFingerprints[githubPartialFingerprintKey]); v != "" {
		return v
	}
	if v := firstBySortedKey(res.PartialFingerprints); v != "" {
		return v
	}
	if v := strings.TrimSpace(res.GUID); v != "" {
		return v
	}
	if v := strings.TrimSpace(res.CorrelationGUID); v != "" {
		return v
	}
	return SynthesizeFingerprint(toolName, res.RuleID, uri, startLineOf(res), res.Message.Text)
}

// firstBySortedKey returns the first non-empty value by sorted key.
func firstBySortedKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// SynthesizeFingerprint derives a deterministic identifier for a result that
// carries none. Deliberately excludes the line number's neighbours and any
// timestamp so an unrelated edit above the finding does not mint a new identity.
func SynthesizeFingerprint(toolName, ruleID, uri string, startLine int, message string) string {
	h := sha256.New()
	for _, part := range []string{
		strings.ToLower(strings.TrimSpace(toolName)),
		strings.TrimSpace(ruleID),
		strings.TrimSpace(uri),
		strconv.Itoa(startLine),
		strings.TrimSpace(message),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// startLineOf returns the primary location's start line, or 0.
func startLineOf(res *Result) int {
	if res == nil || len(res.Locations) == 0 {
		return 0
	}
	pl := res.Locations[0].PhysicalLocation
	if pl == nil || pl.Region == nil {
		return 0
	}
	return pl.Region.StartLine
}
