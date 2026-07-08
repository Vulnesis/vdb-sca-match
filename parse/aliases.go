package parse

// Exported wrappers over internal parser helpers/types that external callers
// (the CLI's dependency-graph and lock-edge builders) reuse. Keeping the
// implementations unexported preserves their internal call sites unchanged
// while giving cross-package consumers a stable surface.

// UVLockFile is the parsed shape of a uv.lock file.
type UVLockFile = uvLockFile

// PylockFile is the parsed shape of a PEP 751 pylock.toml file.
type PylockFile = pylockFile

// NugetLockFile is the parsed shape of a packages.lock.json file.
type NugetLockFile = nugetLockFile

// MixLockHeadRe matches the leading `"name": {...` of an Elixir mix.lock entry.
var MixLockHeadRe = mixLockHeadRe

// ParsePEP508 parses a PEP 508 requirement specifier.
func ParsePEP508(raw string) (name, version, versionSpec string, ok bool) {
	return parsePEP508(raw)
}

// JoinReqContinuations joins backslash line-continuations in a requirements file.
func JoinReqContinuations(data string) []string {
	return joinReqContinuations(data)
}

// IsRequirementsInclude reports whether a requirements line is an -r/-c include.
func IsRequirementsInclude(s string) bool {
	return isRequirementsInclude(s)
}

// CleanLocalVersion strips a leading operator/prefix from a raw version string.
func CleanLocalVersion(v string) string {
	return cleanLocalVersion(v)
}
