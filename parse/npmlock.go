package parse

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type npmLockEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Optional             bool              `json:"optional"`
	Peer                 bool              `json:"peer"`
	Integrity            string            `json:"integrity"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmLockV1Entry struct {
	Version      string                    `json:"version"`
	Dev          bool                      `json:"dev"`
	Optional     bool                      `json:"optional"`
	Integrity    string                    `json:"integrity"`
	Dependencies map[string]npmLockV1Entry `json:"dependencies"`
}

// npmLockPathName returns the package name an install path holds: the part
// after the last "node_modules/", so "node_modules/a/node_modules/@s/b" is
// "@s/b". ok is false for a path outside node_modules: a workspace member's own
// directory ("packages/app"), which is source in the repository, not a release.
func npmLockPathName(path string) (name string, ok bool) {
	const nm = "node_modules/"
	i := strings.LastIndex(path, nm)
	if i < 0 || (i > 0 && path[i-1] != '/') {
		return "", false
	}
	return path[i+len(nm):], true
}

func parsePackageLockJSONScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Supports v1 (dependencies), v2 (both) and v3 (packages).
	var lock struct {
		LockfileVersion int                       `json:"lockfileVersion"`
		Packages        map[string]npmLockEntry   `json:"packages"`
		Dependencies    map[string]npmLockV1Entry `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	var pkgs []ScopedPackage
	seen := make(map[string]bool) // name@version

	if len(lock.Packages) > 0 {
		// Each importer ("" the root, every non-node_modules path a workspace
		// member) declares its direct dependencies. A declared name resolves to
		// the member's own node_modules copy when there is one, else the root's.
		directPaths := map[string]bool{}
		for path, e := range lock.Packages {
			if _, inNM := npmLockPathName(path); inNM {
				continue
			}
			for _, m := range []map[string]string{e.Dependencies, e.DevDependencies, e.OptionalDependencies, e.PeerDependencies} {
				for dep := range m {
					own := "node_modules/" + dep
					if path != "" {
						own = path + "/node_modules/" + dep
					}
					if _, ok := lock.Packages[own]; ok {
						directPaths[own] = true
					} else {
						directPaths["node_modules/"+dep] = true
					}
				}
			}
		}

		paths := make([]string, 0, len(lock.Packages))
		for p := range lock.Packages {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, path := range paths {
			e := lock.Packages[path]
			name, ok := npmLockPathName(path)
			if !ok || e.Link {
				// The root, a workspace member's directory, or the symlink npm
				// writes to it: none is a registry release.
				continue
			}
			if e.Name != "" {
				name = e.Name // an alias ("node_modules/x": {"name": "real-pkg"})
			}
			if !registryVersion(e.Version) {
				continue // git, file or tarball: no comparable version
			}
			id := name + "@" + e.Version
			if seen[id] {
				continue
			}
			seen[id] = true
			scope := ScopeProduction
			switch {
			case e.Dev || e.DevOptional:
				scope = ScopeDevelopment
			case e.Peer:
				scope = ScopePeer
			case e.Optional:
				scope = ScopeOptional
			}
			sp := ScopedPackage{Name: name, Version: e.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath, IsDirect: directPaths[path]}
			if c := normalizeChecksum(e.Integrity); c.Alg != "" {
				sp.Checksums = []PackageChecksum{c}
			}
			pkgs = append(pkgs, sp)
		}
		return pkgs, nil
	}

	// v1: a nested "dependencies" tree. Top-level entries are the hoisted
	// installs; a nested one is a second version under its dependent. v1 does not
	// say which entries the manifest declared, so IsDirect is left to package.json.
	var walk func(deps map[string]npmLockV1Entry)
	walk = func(deps map[string]npmLockV1Entry) {
		for _, name := range sortedV1Keys(deps) {
			e := deps[name]
			if registryVersion(e.Version) && !seen[name+"@"+e.Version] {
				seen[name+"@"+e.Version] = true
				scope := ScopeProduction
				if e.Dev {
					scope = ScopeDevelopment
				} else if e.Optional {
					scope = ScopeOptional
				}
				sp := ScopedPackage{Name: name, Version: e.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath}
				if c := normalizeChecksum(e.Integrity); c.Alg != "" {
					sp.Checksums = []PackageChecksum{c}
				}
				pkgs = append(pkgs, sp)
			}
			walk(e.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return pkgs, nil
}

func sortedV1Keys(m map[string]npmLockV1Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
