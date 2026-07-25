package sarif

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Severity vocabulary. These match the strings vdb-api's severityCounter buckets
// on, so a Finding.Severity can be counted without further translation.
const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityLow           = "low"
	SeverityInformational = "informational"
)

// SeverityFromLevel maps a SARIF result level to the Vulnetix severity
// vocabulary. LevelFromSeverity is its inverse. They live together so the two
// directions cannot drift apart.
func SeverityFromLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	case "none":
		return SeverityInformational
	default:
		return ""
	}
}

// LevelFromSeverity maps a Vulnetix severity back to a SARIF result level.
func LevelFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium, "moderate":
		return "warning"
	default:
		return "note"
	}
}

// SeverityFromScore maps a GitHub code-scanning `security-severity` score
// (a CVSS-like 0.0–10.0 number) onto the severity vocabulary. The thresholds
// are GitHub's published ones, which every tool that emits the property targets.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInformational
	}
}

// NormalizeSeverity folds the many spellings tools use into the vocabulary.
// Returns "" when the input is not a recognised severity word, so callers can
// fall through to the next source rather than defaulting prematurely.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SeverityCritical
	case "high", "important":
		return SeverityHigh
	case "medium", "moderate", "warning":
		return SeverityMedium
	case "low", "minor":
		return SeverityLow
	case "informational", "info", "informative", "none", "unknown", "negligible":
		return SeverityInformational
	default:
		return ""
	}
}

// propString reads a property bag value as a string, tolerating the JSON number
// form (json.Number, float64) that tools use interchangeably for
// security-severity.
func propString(bag PropertyBag, key string) string {
	if bag == nil {
		return ""
	}
	v, ok := bag[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// severityFromSecuritySeverity interprets a security-severity property value,
// which is a numeric score. A non-numeric value is treated as a severity word
// (some tools write "high" into the field despite the spec).
func severityFromSecuritySeverity(raw string) string {
	if raw == "" {
		return ""
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return SeverityFromScore(f)
	}
	return NormalizeSeverity(raw)
}
