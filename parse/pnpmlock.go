package parse

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpm-lock.yaml has changed its package keys three times, and a parser that
// knows one spelling reads zero packages from the others:
//
//	v5.x  packages: "/express/4.21.0:"            ("/@scope/name/1.0.0", peers as "_peer@1.0.0")
//	v6-8  packages: "/express@4.21.0:"            (peers as "(peer@1.0.0)")
//	v9    packages: "express@4.21.0:"  + snapshots: "express@4.21.0(peer@1.0.0):"
//
// Direct dependencies are listed per importer ("." is the root, every other key
// a workspace member's path); a single-project lock before v9 puts the root's
// maps at the top level instead. Before v9 each package carries dev/optional
// flags; v9 dropped them, so the scope is derived by walking the snapshots from
// each importer's declared maps.

type pnpmLockFile struct {
	LockfileVersion      any                        `yaml:"lockfileVersion"`
	Importers            map[string]pnpmImporter    `yaml:"importers"`
	Dependencies         map[string]yaml.Node       `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node       `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node       `yaml:"optionalDependencies"`
	Packages             map[string]pnpmPackage     `yaml:"packages"`
	Snapshots            map[string]pnpmSnapshotRef `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
	Name                 string            `yaml:"name"`
	Version              string            `yaml:"version"`
	Dev                  *bool             `yaml:"dev"`
	Optional             bool              `yaml:"optional"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmSnapshotRef struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// pnpmLockVersion reads lockfileVersion, written as a number (5.4) or a string ('9.0').
func pnpmLockVersion(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(strings.Trim(t, `'"`), 64)
		return f
	}
	return 0
}

// pnpmImporterVersion reads an importer entry, written as a bare version (v5)
// or as {specifier, version} (v6+).
func pnpmImporterVersion(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var obj struct {
		Version string `yaml:"version"`
	}
	_ = n.Decode(&obj)
	return obj.Version
}

// stripPnpmPeers removes the peer-dependency suffix from a version or key:
// "1.0.0(react@18.0.0)" (v6+) and "1.0.0_react@18.0.0" (v5).
func stripPnpmPeers(s string) string {
	if i := strings.Index(s, "("); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "_"); i > 0 {
		s = s[:i]
	}
	return s
}

// splitPnpmKey splits a packages/snapshots key into name and version. legacy
// selects the v5 "/name/version" spelling.
func splitPnpmKey(key string, legacy bool) (name, version string) {
	key = strings.Trim(key, `'"`)
	key = strings.TrimPrefix(key, "/")
	if legacy {
		key = stripPnpmPeers(key)
		i := strings.LastIndex(key, "/")
		if i <= 0 {
			return "", ""
		}
		return key[:i], key[i+1:]
	}
	if i := strings.Index(key, "("); i > 0 {
		key = key[:i]
	}
	start := 0
	if strings.HasPrefix(key, "@") {
		start = 1
	}
	i := strings.Index(key[start:], "@")
	if i < 0 {
		return "", ""
	}
	i += start
	return key[:i], key[i+1:]
}

func parsePnpmLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var lock pnpmLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid pnpm-lock.yaml: %w", err)
	}
	ver := pnpmLockVersion(lock.LockfileVersion)
	legacy := ver > 0 && ver < 6

	importers := lock.Importers
	if len(importers) == 0 && (len(lock.Dependencies) > 0 || len(lock.DevDependencies) > 0 || len(lock.OptionalDependencies) > 0) {
		importers = map[string]pnpmImporter{".": {
			Dependencies:         lock.Dependencies,
			DevDependencies:      lock.DevDependencies,
			OptionalDependencies: lock.OptionalDependencies,
		}}
	}

	// Direct packages and their declared scope, keyed name@version.
	direct := map[string]bool{}
	scope := map[string]string{}
	type item struct{ name, version, scope string }
	var queue []item
	visit := func(name, version, s string) {
		id := name + "@" + stripPnpmPeers(version)
		if prev, ok := scope[id]; ok && bunScopeRank[prev] <= bunScopeRank[s] {
			return
		}
		scope[id] = s
		queue = append(queue, item{name, version, s})
	}
	impPaths := make([]string, 0, len(importers))
	for p := range importers {
		impPaths = append(impPaths, p)
	}
	sort.Strings(impPaths)
	for _, p := range impPaths {
		imp := importers[p]
		for _, m := range []struct {
			deps  map[string]yaml.Node
			scope string
		}{
			{imp.Dependencies, ScopeProduction},
			{imp.OptionalDependencies, ScopeOptional},
			{imp.DevDependencies, ScopeDevelopment},
		} {
			names := make([]string, 0, len(m.deps))
			for n := range m.deps {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, name := range names {
				v := pnpmImporterVersion(m.deps[name])
				if !registryVersion(stripPnpmPeers(v)) {
					continue // link:../lib (a workspace), file:, a tarball URL
				}
				direct[name+"@"+stripPnpmPeers(v)] = true
				visit(name, v, m.scope)
			}
		}
	}

	// Walk the dependency edges (v9: snapshots; earlier: packages) so a package
	// reachable only through a dev dependency is development, as the v5-8 flags say.
	edges := func(name, version string) (map[string]string, map[string]string) {
		if lock.Snapshots != nil {
			s := lock.Snapshots[name+"@"+version]
			return s.Dependencies, s.OptionalDependencies
		}
		key := "/" + name + "@" + version
		if legacy {
			key = "/" + name + "/" + version
		}
		pk := lock.Packages[key]
		return pk.Dependencies, pk.OptionalDependencies
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if scope[it.name+"@"+stripPnpmPeers(it.version)] != it.scope {
			continue
		}
		deps, opt := edges(it.name, it.version)
		for _, d := range sortedKeys(deps) {
			if registryVersion(stripPnpmPeers(deps[d])) {
				visit(d, deps[d], it.scope)
			}
		}
		for _, d := range sortedKeys(opt) {
			if registryVersion(stripPnpmPeers(opt[d])) {
				visit(d, opt[d], weakerScope(it.scope, ScopeOptional))
			}
		}
	}

	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pkgs []ScopedPackage
	seen := map[string]bool{}
	for _, key := range keys {
		pk := lock.Packages[key]
		name, version := splitPnpmKey(key, legacy)
		version = stripPnpmPeers(version)
		if !registryVersion(version) {
			// A git, file or tarball entry: its key carries a URL or path, not a
			// version. Only a tarball served from a registry ("/-/" in the path)
			// is a release of the package it names.
			if pk.Name == "" || pk.Version == "" || !strings.Contains(pk.Resolution.Tarball, "/-/") {
				continue
			}
			name, version = pk.Name, stripPnpmPeers(pk.Version)
		}
		if name == "" || !registryVersion(version) {
			continue
		}
		id := name + "@" + version
		if seen[id] {
			continue
		}
		seen[id] = true

		s, ok := scope[id]
		switch {
		case pk.Dev != nil || pk.Optional:
			// v5-8 recorded the scope; it is the lock's own answer.
			s = ScopeProduction
			if pk.Dev != nil && *pk.Dev {
				s = ScopeDevelopment
			} else if pk.Optional {
				s = ScopeOptional
			}
		case !ok:
			s = ScopeProduction
		}
		sp := ScopedPackage{Name: name, Version: version, Ecosystem: "npm", Scope: s, SourceFile: filePath, IsDirect: direct[id]}
		if c := normalizeChecksum(pk.Resolution.Integrity); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}
