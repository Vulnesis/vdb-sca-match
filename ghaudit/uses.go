package ghaudit

import (
	"regexp"
	"strings"
)

// UsesKind classifies a `uses:` reference.
type UsesKind string

const (
	UsesRemote   UsesKind = "remote"   // owner/repo[/path]@ref
	UsesLocal    UsesKind = "local"    // ./path
	UsesDocker   UsesKind = "docker"   // docker://image
	UsesReusable UsesKind = "reusable" // owner/repo/.github/workflows/x.yml@ref
	UsesInvalid  UsesKind = "invalid"
)

// Uses is a parsed `uses:` value.
type Uses struct {
	Raw   string   `json:"raw"`
	Kind  UsesKind `json:"kind"`
	Owner string   `json:"owner,omitempty"`
	Repo  string   `json:"repo,omitempty"`
	Path  string   `json:"path,omitempty"`
	Ref   string   `json:"ref,omitempty"`
	Image string   `json:"image,omitempty"`
}

// Slug is lowercase owner/repo.
func (u Uses) Slug() string { return strings.ToLower(u.Owner + "/" + u.Repo) }

// Action is owner/repo[/path], as written.
func (u Uses) Action() string {
	if u.Path != "" {
		return u.Owner + "/" + u.Repo + "/" + u.Path
	}
	return u.Owner + "/" + u.Repo
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// PinnedToSHA reports whether the ref is a full commit SHA.
func (u Uses) PinnedToSHA() bool { return shaRe.MatchString(u.Ref) }

// DigestPinned reports whether a docker image reference carries a digest.
func (u Uses) DigestPinned() bool { return strings.Contains(u.Image, "@sha256:") }

// ParseUses parses a `uses:` value.
func ParseUses(raw string) Uses {
	raw = strings.TrimSpace(raw)
	u := Uses{Raw: raw}
	switch {
	case raw == "":
		u.Kind = UsesInvalid
	case strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../"):
		u.Kind = UsesLocal
		u.Path = raw
	case strings.HasPrefix(raw, "docker://"):
		u.Kind = UsesDocker
		u.Image = strings.TrimPrefix(raw, "docker://")
	default:
		at := strings.LastIndex(raw, "@")
		target := raw
		if at >= 0 {
			target, u.Ref = raw[:at], raw[at+1:]
		}
		parts := strings.SplitN(target, "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			u.Kind = UsesInvalid
			return u
		}
		u.Owner, u.Repo = parts[0], parts[1]
		if len(parts) == 3 {
			u.Path = parts[2]
		}
		u.Kind = UsesRemote
		if strings.Contains(u.Path, ".github/workflows/") {
			u.Kind = UsesReusable
		}
	}
	return u
}

// Obfuscated reports whether a remote reference contains path tricks such as
// `./`, `//`, or `..` segments, which resolve to the same action but defeat
// string-matching allow-lists and reviewers.
func (u Uses) Obfuscated() bool {
	if u.Kind != UsesRemote && u.Kind != UsesReusable {
		return false
	}
	p := u.Path
	return strings.Contains(p, "./") || strings.Contains(p, "//") || strings.HasSuffix(p, "/") ||
		strings.Contains(u.Raw, "/./") || strings.Contains(u.Raw, "/../")
}

// versionCommentRe reads a `# v1.2.3` comment after a SHA pin.
var versionCommentRe = regexp.MustCompile(`#\s*(?:tag[=:]?\s*)?(v?\d+(?:\.\d+){0,2}[\w.-]*)`)

// PinComment returns the version comment trailing a uses: line, if any.
func PinComment(line string) string {
	if m := versionCommentRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// firstPartyOwners are owners whose actions are published by GitHub itself.
var firstPartyOwners = map[string]bool{"actions": true, "github": true}

// IsFirstParty reports whether the action is published by GitHub.
func (u Uses) IsFirstParty() bool { return firstPartyOwners[strings.ToLower(u.Owner)] }

// popularOwners is the typosquat reference set: owners whose actions are run
// in a large share of public workflows.
var popularOwners = []string{
	"actions", "github", "docker", "aws-actions", "azure", "google-github-actions",
	"hashicorp", "codecov", "peter-evans", "softprops", "goreleaser", "pypa",
	"sigstore", "slsa-framework", "step-security", "ossf", "dependabot", "renovatebot",
	"golangci", "pnpm", "oven-sh", "denoland", "ruby", "gradle", "jfrog", "snyk",
}

// NearPopularOwner returns the popular owner that owner is one edit away
// from, or "" when it is an exact match or not close to any.
func NearPopularOwner(owner string) string {
	o := strings.ToLower(owner)
	for _, p := range popularOwners {
		if o == p {
			return ""
		}
	}
	for _, p := range popularOwners {
		if len(p) >= 5 && editDistanceAtMostOne(o, p) {
			return p
		}
	}
	return ""
}

func editDistanceAtMostOne(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	i, j, edits := 0, 0, 0
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		edits++
		if edits > 1 {
			return false
		}
		switch {
		case la > lb:
			i++
		case lb > la:
			j++
		default:
			// Adjacent transposition counts as one edit.
			if i+1 < la && j+1 < lb && a[i] == b[j+1] && a[i+1] == b[j] {
				i += 2
				j += 2
				continue
			}
			i++
			j++
		}
	}
	return edits+(la-i)+(lb-j) <= 1
}

// deprecatedMajors lists action majors whose runtime GitHub has retired
// (node12/node16) or whose artifact backend has been shut down.
var deprecatedMajors = map[string]map[string]string{
	"actions/checkout":          {"v1": "node12", "v2": "node12", "v3": "node16"},
	"actions/setup-node":        {"v1": "node12", "v2": "node12", "v3": "node16"},
	"actions/setup-python":      {"v1": "node12", "v2": "node12", "v3": "node16"},
	"actions/setup-go":          {"v1": "node12", "v2": "node12", "v3": "node16"},
	"actions/setup-java":        {"v1": "node12", "v2": "node12", "v3": "node16"},
	"actions/cache":             {"v1": "node12", "v2": "node12", "v3": "retired cache service"},
	"actions/upload-artifact":   {"v1": "retired artifact service", "v2": "retired artifact service", "v3": "retired artifact service"},
	"actions/download-artifact": {"v1": "retired artifact service", "v2": "retired artifact service", "v3": "retired artifact service"},
	"actions/github-script":     {"v1": "node12", "v2": "node12", "v3": "node12", "v4": "node12", "v5": "node16", "v6": "node16"},
	"github/codeql-action":      {"v1": "retired", "v2": "retired"},
}

// DeprecatedReason returns why a tag-pinned action major is retired, or "".
func (u Uses) DeprecatedReason() string {
	majors := deprecatedMajors[u.Slug()]
	if majors == nil {
		return ""
	}
	ref := strings.ToLower(u.Ref)
	if i := strings.Index(ref, "."); i > 0 {
		ref = ref[:i]
	}
	return majors[ref]
}
