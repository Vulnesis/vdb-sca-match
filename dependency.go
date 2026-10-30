package match

// Dependency is a single software dependency to be matched against the VDB.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	Purl      string
	Cpe       string
	License   string
	Key       string // unique identifier (e.g. cdxId:name:version or name:version)

	// NativeOnly, with an empty Ecosystem, matches only advisories that name
	// no package registry or distribution: software as its upstream ships it.
	// MatchOSPackage sets it for its upstream pass, so an OS package "tar" is
	// not matched against the npm package of the same name.
	NativeOnly bool

	// Release, with a distribution Ecosystem, is the installed release as OSV
	// names it ("debian:12", "ubuntu:22.04", "alpine:v3.18"; DistroRelease).
	// A distribution row tagged with another release is skipped; a row that
	// names no release still applies.
	Release string
}
