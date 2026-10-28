package ghaudit

import (
	"fmt"
	"regexp"
	"strings"
)

// usesSite is one `uses:` reference with where it appears.
type usesSite struct {
	f    *File
	j    *Job
	s    *Step // nil for a job-level reusable workflow call
	v    *Value
	u    Uses
	line string
}

func (c *Context) usesSites() []usesSite {
	var out []usesSite
	for _, f := range c.Files() {
		for _, j := range f.Jobs {
			if j.Uses != nil {
				out = append(out, usesSite{f: f, j: j, v: j.Uses, u: ParseUses(j.Uses.Text), line: f.Line(j.Uses.Pos.Line)})
			}
			for _, s := range j.Steps {
				if s.Uses != nil {
					out = append(out, usesSite{f: f, j: j, s: s, v: s.Uses, u: ParseUses(s.Uses.Text), line: f.Line(s.Uses.Pos.Line)})
				}
			}
		}
	}
	return out
}

func (us usesSite) scope() string {
	if us.s == nil {
		return us.j.ID
	}
	return us.j.ID + "/" + stepKey(us.s)
}

func (us usesSite) loc() Location {
	l := at(us.f, us.v.Pos, us.j, us.s)
	return l
}

func (c *Context) refFacts(u Uses) *ActionRefFacts {
	if c.Facts == nil || c.Facts.Actions == nil {
		return nil
	}
	return c.Facts.Actions[u.Raw]
}

var branchLikeRefs = map[string]bool{"main": true, "master": true, "develop": true, "dev": true, "trunk": true, "head": true, "latest": true, "stable": true, "release": true, "nightly": true, "canary": true}

var ruleUnpinned = register(&Rule{
	ID: "VNX-GH-101", Name: "Action or reusable workflow not pinned to a commit SHA", Task: TaskActions,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{829, 494}, ATTACK: []string{"T1195.001"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "pinning"},
	Summary:     "uses: references a branch or tag, which the action's owner (or anyone who compromises them) can move.",
	Description: "Tags and branches are mutable. When an action repository is compromised, the attacker re-points existing tags at malicious code and every workflow referencing them runs it on its next execution — as happened in widely used actions. A full 40-character SHA is the only immutable reference.",
	Remediation: "Pin to the full commit SHA and keep the version in a trailing comment (uses: owner/repo@<sha> # v1.2.3); let Dependabot or Renovate update both.",
	Enhances:    []string{FactActionRefs, FactActionsPolicy, FactRepo},
	check: func(c *Context) []*Finding {
		var out []*Finding
		owner := strings.ToLower(strings.SplitN(c.In.Repository, "/", 2)[0])
		for _, us := range c.usesSites() {
			if (us.u.Kind != UsesRemote && us.u.Kind != UsesReusable) || us.u.PinnedToSHA() {
				continue
			}
			fd := &Finding{
				Subject:  subject(us.f, us.scope(), "pin", us.u.Slug()),
				Location: us.loc(),
				Evidence: map[string]any{"uses": us.u.Raw, "ref": us.u.Ref},
			}
			ref := strings.ToLower(us.u.Ref)
			switch {
			case us.u.Ref == "":
				fd.Severity = High
				fd.Message = fmt.Sprintf("%s has no ref and follows the default branch.", us.u.Raw)
			case branchLikeRefs[ref]:
				fd.Severity = High
				fd.Message = fmt.Sprintf("%s follows branch %q; every push to it runs here.", us.u.Raw, us.u.Ref)
			default:
				fd.Message = fmt.Sprintf("%s is pinned to tag %q, which can be re-pointed.", us.u.Raw, us.u.Ref)
			}
			if rf := c.refFacts(us.u); rf != nil {
				fd.Evidence["resolvedSha"] = rf.SHA
				if rf.RefType == "branch" && fd.Severity != High {
					fd.Severity = High
					fd.adjust(0, "ref resolves to a branch, not a tag")
				}
				if rf.SHA != "" {
					fd.Fix = &Fix{Description: fmt.Sprintf("Pin to %s.", rf.SHA), Edits: []Edit{{
						Path: us.f.Path, StartLine: us.v.Pos.Line, EndLine: us.v.Pos.Line,
						Replacement: pinLine(us.line, us.u, rf.SHA),
					}}}
				}
			}
			switch {
			case us.u.IsFirstParty():
				fd.adjust(-1, "action is published by GitHub")
			case owner != "" && strings.EqualFold(us.u.Owner, owner):
				fd.adjust(-1, "action belongs to the same owner as this repository")
			}
			if r := c.Repo(); r != nil && boolp(r.SHAPinningRequired) {
				fd.adjust(1, "repository policy requires SHA pinning, so this reference will fail to run")
				fd.Confidence = ConfidenceHigh
			}
			out = append(out, fd)
		}
		return out
	},
})

func pinLine(line string, u Uses, sha string) string {
	comment := ""
	if u.Ref != "" {
		comment = " # " + u.Ref
	}
	at := strings.Index(line, u.Raw)
	if at < 0 {
		return line
	}
	pinned := u.Action() + "@" + sha
	rest := line[at+len(u.Raw):]
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = strings.TrimRight(rest[:i], " ")
	}
	return line[:at] + pinned + rest + comment
}

var rulePinMismatch = register(&Rule{
	ID: "VNX-GH-102", Name: "SHA pin does not match its version comment", Task: TaskActions,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{345, 451},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "pinning"},
	Summary:     "uses: owner/repo@<sha> # vX.Y.Z, but vX.Y.Z resolves to a different commit.",
	Description: "Reviewers and update bots read the version comment, not the SHA. A SHA that does not match its comment either predates an update that only changed the comment, or was swapped deliberately to run a different commit under a trusted-looking version.",
	Remediation: "Re-pin to the commit the intended version resolves to, and update the comment and SHA together.",
	Requires:    []string{FactActionRefs},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			if !us.u.PinnedToSHA() {
				continue
			}
			rf := c.refFacts(us.u)
			comment := PinComment(us.line)
			if rf == nil || comment == "" || rf.CommentSHA == "" || strings.EqualFold(rf.CommentSHA, us.u.Ref) {
				continue
			}
			out = append(out, &Finding{
				Subject:  subject(us.f, us.scope(), "pin-comment", us.u.Slug()),
				Location: us.loc(),
				Message:  fmt.Sprintf("%s is commented %s, but %s resolves to %s.", us.u.Raw, comment, comment, rf.CommentSHA),
				Evidence: map[string]any{"pinned": us.u.Ref, "comment": comment, "commentSha": rf.CommentSHA},
				Fix:      &Fix{Description: "Pin to the commented version's commit.", Edits: []Edit{{Path: us.f.Path, StartLine: us.v.Pos.Line, EndLine: us.v.Pos.Line, Replacement: strings.Replace(us.line, us.u.Ref, rf.CommentSHA, 1)}}},
			})
		}
		return out
	},
})

var ruleImpostor = register(&Rule{
	ID: "VNX-GH-103", Name: "Pinned commit is not in the action's repository", Task: TaskActions,
	Severity: Critical, Confidence: ConfidenceHigh, CWE: []int{345, 494}, ATTACK: []string{"T1195.001"},
	CWSS:        "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "impostor-commit"},
	Summary:     "The pinned SHA exists only in a fork of the action repository.",
	Description: "GitHub serves commits from any fork through the parent repository's URL. An attacker can push malicious code to a fork and propose a pin to that SHA; it looks like owner/repo@<sha> but the commit was never part of owner/repo.",
	Remediation: "Replace the SHA with one that is reachable from a branch or tag of the action repository itself.",
	Requires:    []string{FactActionRefs},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			if !us.u.PinnedToSHA() {
				continue
			}
			rf := c.refFacts(us.u)
			if rf == nil || rf.ReachableFromRepo == nil || *rf.ReachableFromRepo {
				continue
			}
			out = append(out, &Finding{
				Subject:  subject(us.f, us.scope(), "impostor", us.u.Slug()),
				Location: us.loc(),
				Message:  fmt.Sprintf("Commit %s is not reachable from any branch or tag of %s/%s.", us.u.Ref, us.u.Owner, us.u.Repo),
				Evidence: map[string]any{"sha": us.u.Ref},
			})
		}
		return out
	},
})

var ruleAbandoned = register(&Rule{
	ID: "VNX-GH-104", Name: "Action repository archived, missing or hijackable", Task: TaskActions,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{1104, 494}, ATTACK: []string{"T1195.001"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "repojacking"},
	Summary:     "The referenced action is archived, deleted, or its owner was renamed or removed.",
	Description: "An archived action gets no security fixes. A deleted repository, or an owner that was renamed or removed, lets anyone register the old name and publish code under it (repo-jacking); unpinned references then run it.",
	Remediation: "Replace the action with a maintained alternative, or vendor it into this repository as a local action.",
	Requires:    []string{FactActionRefs},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			rf := c.refFacts(us.u)
			if rf == nil {
				continue
			}
			var why string
			sev := High
			switch {
			case rf.OwnerMissing:
				why, sev = fmt.Sprintf("owner %q no longer exists; anyone can claim the name", us.u.Owner), Critical
			case rf.RepoMissing:
				why = fmt.Sprintf("repository %s/%s no longer exists", us.u.Owner, us.u.Repo)
			case rf.RedirectedTo != "":
				why = fmt.Sprintf("repository was renamed or transferred to %s; the old name can be re-registered", rf.RedirectedTo)
			case rf.RepoArchived:
				why, sev = "repository is archived and receives no fixes", Medium
			default:
				continue
			}
			fd := &Finding{Subject: subject(us.f, us.scope(), "abandoned", us.u.Slug()), Location: us.loc(), Severity: sev, Message: fmt.Sprintf("%s: %s.", us.u.Raw, why), Evidence: map[string]any{"redirectedTo": rf.RedirectedTo, "archived": rf.RepoArchived}}
			if us.u.PinnedToSHA() && (rf.OwnerMissing || rf.RedirectedTo != "") {
				fd.adjust(-1, "reference is pinned to a SHA, so a re-registered repository cannot serve a different commit for it")
			}
			out = append(out, fd)
		}
		return out
	},
})

var ruleVulnerable = register(&Rule{
	ID: "VNX-GH-105", Name: "Action version has a published vulnerability", Task: TaskActions,
	Severity: High, Confidence: ConfidenceHigh, CWE: []int{1395},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "vulnerable-dependency"},
	Summary:     "The referenced version of the action is affected by a known advisory.",
	Description: "Actions are dependencies. A vulnerable version — command injection through its inputs, credential leakage, or a compromised release — exposes every workflow that runs it.",
	Remediation: "Upgrade to the fixed version named in the advisory and re-pin to its SHA.",
	Requires:    []string{FactActionRefs},
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			rf := c.refFacts(us.u)
			if rf == nil {
				continue
			}
			for _, a := range rf.Advisories {
				fd := &Finding{
					Subject:  subject(us.f, us.scope(), "advisory", us.u.Slug(), strings.ToLower(a.ID)),
					Location: us.loc(),
					Title:    fmt.Sprintf("%s %s is affected by %s", us.u.Action(), us.u.Ref, a.ID),
					Message:  fmt.Sprintf("%s is affected by %s: %s.", us.u.Raw, a.ID, a.Summary),
					Evidence: map[string]any{"advisory": a.ID, "fixedIn": a.FixedIn, "url": a.URL},
				}
				if s := ParseSeverity(a.Severity); s != "" {
					fd.Severity = s
				}
				out = append(out, fd)
			}
		}
		return out
	},
})

var ruleUnpinnedImage = register(&Rule{
	ID: "VNX-GH-106", Name: "Container image not pinned to a digest", Task: TaskActions,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{829, 494},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "containers"},
	Summary:     "docker:// steps, job containers and services reference an image by tag.",
	Description: "Image tags are mutable. The image that runs with the job's token and workspace can change without any change to the workflow.",
	Remediation: "Reference images by digest (image@sha256:...), and let an update bot refresh it.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			if us.u.Kind != UsesDocker || us.u.DigestPinned() {
				continue
			}
			out = append(out, &Finding{Subject: subject(us.f, us.scope(), "image", slug(us.u.Image)), Location: us.loc(), Message: fmt.Sprintf("Step runs image %s by tag.", us.u.Image)})
		}
		for _, f := range c.Files() {
			if f.Kind == KindDockerAction && f.ActionMain != "" && strings.HasPrefix(f.ActionMain, "docker://") && !strings.Contains(f.ActionMain, "@sha256:") {
				out = append(out, &Finding{Subject: subject(f, "runs", "image"), Location: Location{Path: f.Path, StartLine: 1}, Message: fmt.Sprintf("Action runs image %s by tag.", f.ActionMain)})
			}
			for _, j := range f.Jobs {
				cs := append([]*Container{}, j.Services...)
				if j.Container != nil {
					cs = append(cs, j.Container)
				}
				for _, ct := range cs {
					img := strings.TrimSpace(ct.Image.Text)
					if img == "" || strings.Contains(img, "@sha256:") || len(Expressions(img)) > 0 {
						continue
					}
					out = append(out, &Finding{Subject: subject(f, j.ID, "image", slug(img)), Location: Location{Path: f.Path, StartLine: ct.Image.Pos.Line, EndLine: ct.Image.Pos.Line, Job: j.ID, Snippet: strings.TrimSpace(f.Line(ct.Image.Pos.Line))}, Message: fmt.Sprintf("Job %q uses image %s by tag.", j.ID, img)})
				}
			}
		}
		return out
	},
})

var ruleDeprecated = register(&Rule{
	ID: "VNX-GH-107", Name: "Action major version runs on a retired runtime", Task: TaskActions,
	Severity: Low, Confidence: ConfidenceHigh, CWE: []int{1104},
	CWSS:        "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "maintenance"},
	Summary:     "The action version uses a Node.js runtime or backend service GitHub has retired.",
	Description: "Retired runtimes receive no security patches and are forced onto newer runtimes by the runner, which can change behaviour; retired artifact and cache backends fail outright.",
	Remediation: "Upgrade to the current major version of the action.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			if us.u.Kind != UsesRemote {
				continue
			}
			ref := us.u.Ref
			if us.u.PinnedToSHA() {
				ref = PinComment(us.line)
			}
			why := Uses{Owner: us.u.Owner, Repo: us.u.Repo, Ref: ref}.DeprecatedReason()
			if why == "" {
				continue
			}
			out = append(out, &Finding{Subject: subject(us.f, us.scope(), "deprecated", us.u.Slug()), Location: us.loc(), Message: fmt.Sprintf("%s@%s depends on a %s.", us.u.Action(), ref, why)})
		}
		return out
	},
})

var rulePolicy = register(&Rule{
	ID: "VNX-GH-108", Name: "Action not permitted by the allowed-actions policy", Task: TaskActions,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{284},
	CWSS:        "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "policy"},
	Summary:     "The workflow references an action that the repository's allowed-actions policy does not list.",
	Description: "The run will fail at start-up, or — if the policy is relaxed to make it pass — the allow-list stops meaning anything. Either way the drift should be resolved deliberately.",
	Remediation: "Replace the action with an allowed one, or add it (pinned) to the allow-list after review.",
	Requires:    []string{FactActionsPolicy},
	check: func(c *Context) []*Finding {
		r := c.Repo()
		if r == nil || r.AllowedActions != "selected" {
			return nil
		}
		var out []*Finding
		owner := strings.ToLower(strings.SplitN(c.In.Repository, "/", 2)[0])
		for _, us := range c.usesSites() {
			if us.u.Kind != UsesRemote && us.u.Kind != UsesReusable {
				continue
			}
			if strings.EqualFold(us.u.Owner, owner) || (boolp(r.GithubOwnedAllowed) && us.u.IsFirstParty()) {
				continue
			}
			if rf := c.refFacts(us.u); rf != nil && rf.Verified && boolp(r.VerifiedAllowed) {
				continue
			}
			if allowedByPatterns(us.u, r.AllowedActionPatterns) {
				continue
			}
			out = append(out, &Finding{Subject: subject(us.f, us.scope(), "policy", us.u.Slug()), Location: us.loc(), Message: fmt.Sprintf("%s is not in the repository's allowed-actions list.", us.u.Raw)})
		}
		return out
	},
})

func allowedByPatterns(u Uses, pats []string) bool {
	target := strings.ToLower(u.Action() + "@" + u.Ref)
	for _, p := range pats {
		p = strings.ToLower(strings.TrimSpace(p))
		re := "^" + strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, ".*")
		if !strings.Contains(p, "@") {
			re += "(@.*)?"
		}
		if regexp.MustCompile(re + "$").MatchString(target) {
			return true
		}
	}
	return false
}

var ruleTyposquat = register(&Rule{
	ID: "VNX-GH-109", Name: "Action owner resembles a popular publisher", Task: TaskActions,
	Severity: High, Confidence: ConfidenceMedium, CWE: []int{1357}, ATTACK: []string{"T1195.001"},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain", "typosquatting"},
	Summary:     "The action's owner is one character away from a widely used publisher.",
	Description: "Typosquatted owners (actoins/checkout, aws-action/...) are registered to catch mistyped references and run attacker code with the job's privileges.",
	Remediation: "Check the owner's spelling; reference the intended publisher.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, us := range c.usesSites() {
			if us.u.Kind != UsesRemote && us.u.Kind != UsesReusable {
				continue
			}
			near := NearPopularOwner(us.u.Owner)
			if near == "" {
				continue
			}
			out = append(out, &Finding{Subject: subject(us.f, us.scope(), "typosquat", us.u.Slug()), Location: us.loc(), Message: fmt.Sprintf("Owner %q is one edit away from %q.", us.u.Owner, near), Evidence: map[string]any{"similarTo": near}})
		}
		return out
	},
})

var pipeShellRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|iex)\b`)

var rulePipeShell = register(&Rule{
	ID: "VNX-GH-111", Name: "Remote script piped into an interpreter", Task: TaskActions,
	Severity: Medium, Confidence: ConfidenceHigh, CWE: []int{494, 829},
	CWSS:        "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:L/EC:N/P:W",
	Tags:        []string{"ci-cd", "github-actions", "supply-chain"},
	Summary:     "A run: step downloads a script and executes it without verifying it.",
	Description: "curl | sh runs whatever the server returns at that moment, with the job's token and secrets. A compromised host, CDN or DNS response becomes code execution in CI.",
	Remediation: "Download to a file, verify a pinned checksum or signature, then execute it — or use a pinned action or package instead.",
	check: func(c *Context) []*Finding {
		var out []*Finding
		for _, f := range c.Files() {
			for _, j := range f.Jobs {
				for _, s := range j.Steps {
					if s.Run == nil {
						continue
					}
					for i, line := range strings.Split(s.Run.Text, "\n") {
						if !pipeShellRe.MatchString(line) {
							continue
						}
						p := f.Locate(s.Run.Pos.Line+boolInt(s.Run.Block)+i-1, strings.TrimSpace(line))
						fd := &Finding{Subject: subject(f, j.ID, stepKey(s), "pipe-shell"), Location: at(f, p, j, s), Message: fmt.Sprintf("Step %q pipes a downloaded script into an interpreter.", stepKey(s))}
						if _, ok := privileged(f); ok {
							fd.adjust(1, "workflow runs with a write token on a trigger reachable by outsiders")
						}
						out = append(out, fd)
						break
					}
				}
			}
		}
		return out
	},
})
