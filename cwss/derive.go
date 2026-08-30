package cwss

import "strings"

// Deriving a CWSS vector for a rule-engine finding.
//
// A SAST, secrets, IaC or container finding has no CVE, so nothing hands it a
// CVSS score, and with no score at all every one of them displays as "unknown".
// What such a finding does have is the rule's declared severity, the weakness it
// maps to, and the fact that our own analysis just found it in source we hold.
// That is enough to fill CWSS honestly.
//
// Two things this deliberately does NOT do:
//
//   - It does not start from Unknown and set one metric. CWSS multiplies its
//     three groups, so a vector that is UK everywhere but Technical Impact
//     scores 0.26–0.44 whatever the severity says — every finding "low", which
//     is worse than every finding "unknown" because it looks decided.
//   - It does not force the score into the band the rule declared. A critical
//     weakness that an attacker can only reach with local access really is less
//     severe than the same weakness on an internet-facing input path, and CWSS
//     saying so is the point of scoring it rather than relabelling it. Expect
//     local-reach criticals to band as high; DeriveTable pins the whole mapping.

// Reach describes how an attacker gets to the weakness. It is the one axis a
// rule's severity label cannot express and that changes the answer most.
type Reach string

const (
	// ReachRemote: the weakness sits on a path fed by attacker-controlled input
	// crossing a trust boundary — injection, deserialization, SSRF, auth bypass.
	ReachRemote Reach = "remote"
	// ReachLocal: reaching the weakness needs local or already-authenticated
	// access — weak crypto, unsafe permissions, hardening and configuration.
	ReachLocal Reach = "local"
)

// Input is what the caller knows about one finding.
type Input struct {
	// Severity is the rule's declared severity, in the sarif package's
	// vocabulary: critical | high | medium | low | informational.
	Severity string
	// CWEs the rule maps to. Drives Reach when Reach is empty.
	CWEs []int
	// Tags from the rule metadata, consulted after CWEs.
	Tags []string
	// Kind is the rule's own taxonomy — sast | secrets | iac | oci. A secrets
	// rule is a credential exposure by definition, so it never needs the CWE
	// route to reach the right answer.
	Kind string
	// Reach overrides the CWE/tag inference when the caller already knows.
	Reach Reach
}

// baseline states what is true of any finding our own rule engine reports
// against source we hold. Every one of these is a claim we can defend:
//
//	FC:LT  proven locally true — the rule matched this code, which is not the
//	       same as a demonstrated exploit, so not FC:T
//	IC:N   no in-code compensating control was found; had there been one the
//	       rule would not have fired
//	EC:N   no external control is recorded against it either
//	DI:H   highly discoverable — our own static analysis just discovered it, and
//	       anyone running the same class of tool will too
//	SC:A   present wherever this artefact is deployed
//	AS:N   reaching the weakness needs no authentication of its own
//	IN:A   and no human interaction
var baseline = map[string]string{
	"FC": "LT", "IC": "N", "EC": "N", "DI": "H", "SC": "A", "AS": "N", "IN": "A",
}

// bySeverity expresses the rule's severity on the two axes CWSS splits impact
// across — Technical Impact and Business Impact — plus the exploit likelihood
// and prevalence that track with it. Saying the same thing on TI and BI is the
// mapping, not double counting: a severity label is a single claim about impact
// and CWSS has no single field for it.
var bySeverity = map[string]map[string]string{
	"critical":      {"TI": "C", "BI": "C", "EX": "H", "P": "W"},
	"high":          {"TI": "H", "BI": "H", "EX": "H", "P": "H"},
	"medium":        {"TI": "M", "BI": "M", "EX": "M", "P": "C"},
	"low":           {"TI": "L", "BI": "L", "EX": "L", "P": "L"},
	"informational": {"TI": "N", "BI": "N", "EX": "N", "P": "L"},
}

// byReach fills the privilege and access-vector metrics.
var byReach = map[Reach]map[string]string{
	ReachRemote: {"AV": "I", "RP": "N", "RL": "A", "AP": "A", "AL": "A"},
	ReachLocal:  {"AV": "L", "RP": "RU", "RL": "S", "AP": "RU", "AL": "S"},
}

// Derive builds a CWSS vector for a rule finding. It never fails: an
// unrecognised severity is treated as medium, which is what a rule that declines
// to say is asserting in practice.
func Derive(in Input) Metrics {
	sev := normaliseSeverity(in.Severity)
	reach := in.Reach
	if reach == "" {
		reach = ReachForRule(in.Kind, in.CWEs, in.Tags)
	}

	m := Unknown()
	apply(m, baseline)
	apply(m, bySeverity[sev])
	apply(m, byReach[reach])
	return m
}

func apply(m Metrics, kv map[string]string) {
	for k, v := range kv {
		_ = m.Set(k, v)
	}
}

func normaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high", "important", "error":
		return "high"
	case "low", "minor", "note":
		return "low"
	case "informational", "info", "informative", "none", "negligible":
		return "informational"
	default:
		// medium, moderate, warning, and anything unrecognised.
		return "medium"
	}
}

// remoteCWEs are the weakness classes an attacker can reach without already
// holding access to the host or the build pipeline. Three families qualify:
//
//   - Input handling: attacker-controlled data crossing a trust boundary —
//     injection, deserialization, traversal, SSRF, XXE, redirect.
//   - Authentication, authorization, session and transport crypto: the failure
//     IS the way in, so forging a token or stripping TLS needs nothing else.
//   - Credential exposure: a key committed to source is not a local problem.
//     Whoever reads the repository authenticates to the live service over the
//     internet, so the exploit path is remote even though the weakness is a
//     string in a file. CWE-798 alone covers 408 of the ruleset's critical
//     rules, and calling those local under-scored every one of them.
//
// Everything absent is treated as local, which is the conservative direction: a
// weakness wrongly called local scores lower, and that is a smaller error than
// one wrongly announced as internet facing.
var remoteCWEs = map[int]bool{
	// Input handling.
	20: true, 22: true, 23: true, 36: true, 74: true, 77: true, 78: true,
	79: true, 88: true, 89: true, 90: true, 91: true, 93: true, 94: true,
	95: true, 96: true, 98: true, 113: true, 116: true, 117: true, 172: true,
	184: true, 400: true, 434: true, 441: true, 444: true, 470: true,
	501: true, 502: true, 601: true, 610: true, 611: true, 643: true,
	652: true, 776: true, 784: true, 827: true, 829: true, 913: true,
	915: true, 917: true, 918: true, 942: true, 943: true, 1275: true,
	1321: true, 1333: true, 1336: true,
	// Authentication, authorization, session, transport crypto.
	130: true, 287: true, 288: true, 290: true, 294: true, 295: true,
	297: true, 300: true, 306: true, 307: true, 322: true, 323: true,
	325: true, 326: true, 327: true, 328: true, 330: true, 335: true,
	338: true, 340: true, 345: true, 346: true, 347: true, 349: true,
	352: true, 354: true, 384: true, 425: true, 565: true, 613: true,
	614: true, 639: true, 640: true, 757: true, 862: true, 863: true,
	1004: true,
	// Credential exposure.
	256: true, 257: true, 259: true, 260: true, 261: true, 319: true,
	321: true, 522: true, 523: true, 798: true,
}

// remoteTags catch the rules whose CWE is generic or absent but whose subject is
// unambiguously an attacker-facing surface.
var remoteTags = map[string]bool{
	"injection": true, "xss": true, "ssrf": true, "csrf": true, "deserialization": true,
	"xxe": true, "traversal": true, "rce": true, "sqli": true, "auth-bypass": true,
	"open-redirect": true, "request-smuggling": true, "network": true, "web": true,
	"secrets": true, "credentials": true, "hardcoded-credentials": true,
	"authentication": true, "broken-auth": true, "jwt": true, "mitm": true, "tls": true,
}

// ReachForRule infers Reach from a rule's kind, then its CWEs, then its tags.
func ReachForRule(kind string, cwes []int, tags []string) Reach {
	if strings.EqualFold(strings.TrimSpace(kind), "secrets") {
		return ReachRemote
	}
	return ReachFor(cwes, tags)
}

// ReachFor infers Reach from a rule's CWEs, then its tags, defaulting to local.
func ReachFor(cwes []int, tags []string) Reach {
	for _, c := range cwes {
		if remoteCWEs[c] {
			return ReachRemote
		}
	}
	for _, t := range tags {
		if remoteTags[strings.ToLower(strings.TrimSpace(t))] {
			return ReachRemote
		}
	}
	return ReachLocal
}
