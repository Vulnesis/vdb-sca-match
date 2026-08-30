// Package cwss implements CWSS 1.0.1 (Common Weakness Scoring System) scoring,
// plus the derivation Vulnetix uses to score a rule-engine finding that has no
// CVE and therefore no CVSS.
//
// Two things live here rather than in either service, because vdb-api scores at
// ingest and vdb-site scores on backfill, and a finding that changed score
// depending on which one got to it first would be worse than one with no score
// at all.
//
// The vector is authoritative and the numeric score is derived from it. Callers
// persist both: the vector so the band can be recomputed and explained, the
// score so SQL can order and bucket without parsing.
package cwss

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Version prefix every vector we emit carries.
const Version = "CWSS:1.0"

// Metric keys, in the order Vector() renders them. This is the full CWSS 1.0.1
// metric set: the Base Finding group, the Attack Surface group, and the
// Environmental group.
var MetricOrder = []string{
	// Base finding
	"TI", "AP", "AL", "IC", "FC",
	// Attack surface
	"RP", "RL", "AV", "AS", "IN", "SC",
	// Environmental
	"BI", "DI", "EX", "EC", "P",
}

// metricValues maps each metric to its permitted value codes and their weights,
// verbatim from CWSS 1.0.1. Anything outside these tables is not CWSS, and Parse
// rejects it rather than silently scoring it as Unknown — a vector that reads
// like CWSS but scores like noise is the failure mode this guards against.
var metricValues = map[string]map[string]float64{
	"TI": {"UK": 0.5, "N": 0.0, "L": 0.3, "M": 0.6, "H": 0.9, "C": 1.0},
	"AP": {"UK": 0.5, "N": 0.1, "L": 0.6, "RU": 0.7, "P": 0.9, "A": 1.0, "R": 1.0},
	"AL": {"UK": 0.5, "A": 1.0, "S": 0.9, "N": 0.7, "E": 1.0},
	"IC": {"UK": 0.5, "N": 1.0, "L": 0.9, "M": 0.7, "I": 0.5, "B": 0.3, "C": 0.0},
	"FC": {"UK": 0.5, "F": 0.0, "LT": 0.8, "T": 1.0},
	"RP": {"UK": 0.5, "N": 1.0, "L": 0.9, "RU": 0.7, "P": 0.6, "A": 0.1},
	"RL": {"UK": 0.5, "A": 1.0, "S": 0.9, "N": 0.7, "E": 1.0},
	"AV": {"UK": 0.5, "I": 1.0, "R": 0.8, "V": 0.8, "A": 0.7, "L": 0.5, "P": 0.2},
	"AS": {"UK": 0.5, "N": 1.0, "W": 0.9, "M": 0.8, "S": 0.7},
	"IN": {"UK": 0.5, "A": 1.0, "T": 0.9, "M": 0.8, "O": 0.3, "H": 0.1, "NI": 0.0},
	"SC": {"UK": 0.5, "A": 1.0, "M": 0.9, "R": 0.5, "P": 0.1},
	"BI": {"UK": 0.5, "N": 0.0, "L": 0.3, "M": 0.6, "H": 0.9, "C": 1.0},
	"DI": {"UK": 0.5, "L": 0.2, "M": 0.6, "H": 1.0},
	"EX": {"UK": 0.5, "N": 0.0, "L": 0.2, "M": 0.6, "H": 1.0},
	"EC": {"UK": 0.5, "N": 1.0, "L": 0.9, "M": 0.7, "I": 0.5, "B": 0.3, "C": 0.1},
	"P":  {"UK": 0.5, "L": 0.7, "C": 0.8, "H": 0.9, "W": 1.0},
}

// Metrics is one finding's CWSS metric selection, keyed by metric short name and
// holding the value CODE (not the weight) so a vector round-trips exactly.
type Metrics map[string]string

// Unknown returns a Metrics with every metric at UK, the CWSS "not assessed"
// value. Scoring it yields ~0.44, which is why nothing in this package emits it
// as a finished score — it is a starting point for Derive, not an answer.
func Unknown() Metrics {
	m := make(Metrics, len(MetricOrder))
	for _, k := range MetricOrder {
		m[k] = "UK"
	}
	return m
}

// Set assigns a metric, rejecting any value outside the CWSS tables.
func (m Metrics) Set(metric, value string) error {
	vals, ok := metricValues[metric]
	if !ok {
		return fmt.Errorf("cwss: %q is not a CWSS metric", metric)
	}
	if _, ok := vals[value]; !ok {
		return fmt.Errorf("cwss: %q is not a value of %s", value, metric)
	}
	m[metric] = value
	return nil
}

// Get returns the value code for a metric, or "UK" when unset.
func (m Metrics) Get(metric string) string {
	if v, ok := m[metric]; ok && v != "" {
		return v
	}
	return "UK"
}

// weight returns the CWSS weight of a metric's current value.
func (m Metrics) weight(metric string) float64 {
	return metricValues[metric][m.Get(metric)]
}

// Vector renders the canonical form: every metric, in MetricOrder, prefixed with
// the version. Always emitting all sixteen means a stored vector never depends
// on the defaults of whatever read it back.
func (m Metrics) Vector() string {
	parts := make([]string, 0, len(MetricOrder)+1)
	parts = append(parts, Version)
	for _, k := range MetricOrder {
		parts = append(parts, k+":"+m.Get(k))
	}
	return strings.Join(parts, "/")
}

// BaseFindingScore is the CWSS Base Finding subscore (0..100).
func (m Metrics) BaseFindingScore() float64 {
	ti := m.weight("TI")
	fTI := 1.0
	if ti == 0 {
		fTI = 0
	}
	v := (10*ti + 5*(m.weight("AP")+m.weight("AL")) + 5*m.weight("FC")) * fTI * m.weight("IC") * 4.0
	return math.Min(v, 100.0)
}

// AttackSurfaceScore is the CWSS Attack Surface multiplier (0..1).
func (m Metrics) AttackSurfaceScore() float64 {
	v := (20*(m.weight("RP")+m.weight("RL")+m.weight("AV")) +
		20*m.weight("SC") + 15*m.weight("IN") + 5*m.weight("AS")) / 100.0
	return math.Min(v, 1.0)
}

// EnvironmentScore is the CWSS Environmental multiplier (0..1).
func (m Metrics) EnvironmentScore() float64 {
	bi := m.weight("BI")
	fBI := 1.0
	if bi == 0 {
		fBI = 0
	}
	v := (10*bi + 3*m.weight("DI") + 4*m.weight("EX") + 3*m.weight("P")) * fBI * m.weight("EC") / 20.0
	return math.Min(v, 1.0)
}

// Score is the CWSS score on the familiar 0..10 scale.
func (m Metrics) Score() float64 {
	return (m.BaseFindingScore() * m.AttackSurfaceScore() * m.EnvironmentScore()) / 10.0
}

// Severity names the band a score falls in, using the same thresholds as CVSS so
// a CWSS-scored finding and a CVSS-scored one sort and filter alike.
//
// A zero score is "informational", not "unknown": CWSS reaches zero only when
// Technical Impact or Business Impact is explicitly None, which is an assessment,
// not an absence of one. Callers with no vector at all should say unknown
// themselves rather than scoring and banding nothing.
func Severity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "informational"
	}
}

// Severity bands this metric set.
func (m Metrics) Severity() string { return Severity(m.Score()) }

// Parse reads a vector string strictly. The version prefix is optional, and both
// the bare `TI:H` form and the `TI:H,0.9` form the browser calculator emits are
// accepted — the embedded weight is redundant and is ignored in favour of the
// table, so a hand-edited weight cannot smuggle in a score.
//
// Unset metrics default to UK. An unrecognised metric or value is an error:
// see Lenient for the reporting variant used by migration tooling.
func Parse(vector string) (Metrics, error) {
	m := Unknown()
	rejects, err := parse(m, vector, true)
	if err != nil {
		return nil, err
	}
	_ = rejects
	return m, nil
}

// Lenient parses as much of a vector as is valid CWSS and returns the
// `metric:value` tokens it could not accept. Used to audit vectors of unknown
// provenance; never used to produce a score for storage, because a vector whose
// metrics mostly fell back to UK scores like noise.
func Lenient(vector string) (Metrics, []string) {
	m := Unknown()
	rejects, _ := parse(m, vector, false)
	return m, rejects
}

func parse(m Metrics, vector string, strict bool) ([]string, error) {
	var rejects []string
	for _, part := range strings.Split(strings.TrimSpace(vector), "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, rest, ok := strings.Cut(part, ":")
		if !ok {
			if strict {
				return nil, fmt.Errorf("cwss: %q is not metric:value", part)
			}
			rejects = append(rejects, part)
			continue
		}
		key = strings.TrimSpace(key)
		// The version prefix is a metric-shaped token that is not a metric.
		if strings.EqualFold(key, "CWSS") {
			continue
		}
		value := strings.TrimSpace(rest)
		if i := strings.IndexByte(value, ','); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		if err := m.Set(key, value); err != nil {
			if strict {
				return nil, err
			}
			rejects = append(rejects, part)
		}
	}
	sort.Strings(rejects)
	return rejects, nil
}
