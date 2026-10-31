package parse

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// bun.lock is the text lockfile Bun has written by default since 1.2 (the
// binary bun.lockb before it cannot be read without Bun and is not parsed). It
// is JSON with trailing commas: a "workspaces" object keyed by workspace path
// ("" is the root) holding each workspace's declared dependency maps, and a
// "packages" object keyed by install path holding one array per installed
// package:
//
//	npm:       [ "name@1.2.3", "<registry or empty>", { dependencies... }, "sha512-..." ]
//	workspace: [ "name@workspace:packages/app" ]
//	git:       [ "name@github:owner/repo#ref", { ... }, "<commit>" ]
//	tarball, file, link: [ "name@<url or path>", { ... } ]
//
// A key is a "/"-joined chain of package names ("express", "app/express",
// "body-parser/debug"): a package not hoisted to the root is keyed below the
// package (or workspace) that pulled it in, and a name is resolved the way Node
// resolves a require: the nearest key up the chain wins.

// BunLock is a parsed bun.lock.
type BunLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Workspaces      map[string]BunWorkspace   `json:"workspaces"`
	Packages        map[string]BunLockPackage `json:"-"`
}

// BunWorkspace is one entry of bun.lock's "workspaces" object.
type BunWorkspace struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// BunLockPackage is one entry of bun.lock's "packages" object.
type BunLockPackage struct {
	Key       string // the install-path key, e.g. "app/express"
	Name      string // the real package name from the ident (differs from the key for an alias)
	Version   string // the resolved version; for a non-registry entry, the resolution after "@"
	Registry  bool   // true when the entry is an npm-registry package (the only kind with a queryable version)
	Workspace bool   // true for a "name@workspace:path" entry
	Integrity string
	// Dependency maps from the entry's info object (child name → declared range).
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
}

// ParseBunLock parses bun.lock bytes.
func ParseBunLock(data []byte) (*BunLock, error) {
	clean := stripJSONTrailingCommas(data)
	var raw struct {
		LockfileVersion int                          `json:"lockfileVersion"`
		Workspaces      map[string]BunWorkspace      `json:"workspaces"`
		Packages        map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(clean, &raw); err != nil {
		return nil, fmt.Errorf("invalid bun.lock: %w", err)
	}
	lock := &BunLock{
		LockfileVersion: raw.LockfileVersion,
		Workspaces:      raw.Workspaces,
		Packages:        make(map[string]BunLockPackage, len(raw.Packages)),
	}
	for key, arr := range raw.Packages {
		if len(arr) == 0 {
			continue
		}
		var ident string
		if err := json.Unmarshal(arr[0], &ident); err != nil {
			continue
		}
		name, res := splitBunIdent(ident)
		if name == "" {
			continue
		}
		p := BunLockPackage{Key: key, Name: name, Version: res}
		switch {
		case strings.HasPrefix(res, "workspace:"):
			p.Workspace = true
		case registryVersion(res) && len(arr) >= 3:
			// [ident, registry, info, integrity]: the shape bun writes only for a
			// registry package. A git, tarball, file or link entry puts the info
			// object second.
			var registry string
			if json.Unmarshal(arr[1], &registry) == nil {
				p.Registry = true
			}
		}
		infoIdx := 1
		if p.Registry {
			infoIdx = 2
			if len(arr) >= 4 {
				_ = json.Unmarshal(arr[3], &p.Integrity)
			}
		}
		if len(arr) > infoIdx {
			var info struct {
				Dependencies         map[string]string `json:"dependencies"`
				OptionalDependencies map[string]string `json:"optionalDependencies"`
				PeerDependencies     map[string]string `json:"peerDependencies"`
			}
			if json.Unmarshal(arr[infoIdx], &info) == nil {
				p.Dependencies = info.Dependencies
				p.OptionalDependencies = info.OptionalDependencies
				p.PeerDependencies = info.PeerDependencies
			}
		}
		lock.Packages[key] = p
	}
	return lock, nil
}

// splitBunIdent splits "name@resolution" at the "@" that ends the name, so a
// scoped name ("@scope/pkg@1.0.0") keeps its leading "@".
func splitBunIdent(ident string) (name, resolution string) {
	start := 0
	if strings.HasPrefix(ident, "@") {
		start = 1
	}
	i := strings.Index(ident[start:], "@")
	if i < 0 {
		return ident, ""
	}
	i += start
	return ident[:i], ident[i+1:]
}

// registryVersion reports whether a resolution is a plain version (what a
// registry entry carries) rather than a protocol (workspace:, github:, file:,
// link:, git+..., a URL). Shared by the bun, pnpm, yarn and npm lock parsers.
func registryVersion(res string) bool {
	if res == "" || res[0] < '0' || res[0] > '9' {
		return false
	}
	return !strings.ContainsAny(res, ":/#")
}

// bunKeyNames splits an install-path key into the package names it chains:
// "app/@types/node" → ["app", "@types/node"].
func bunKeyNames(key string) []string {
	if key == "" {
		return nil
	}
	parts := strings.Split(key, "/")
	var names []string
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			names = append(names, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		names = append(names, parts[i])
	}
	return names
}

// Resolve finds the entry a dependency named dep resolves to from the package
// keyed at parentKey ("" for the root): the nearest key up the chain, as Node
// resolves a require.
func (l *BunLock) Resolve(parentKey, dep string) (BunLockPackage, bool) {
	chain := bunKeyNames(parentKey)
	for n := len(chain); n >= 0; n-- {
		key := dep
		if n > 0 {
			key = strings.Join(chain[:n], "/") + "/" + dep
		}
		if p, ok := l.Packages[key]; ok {
			return p, true
		}
	}
	return BunLockPackage{}, false
}

// workspaceKey is the packages-key prefix under which bun nests a workspace's
// own non-hoisted dependencies: the workspace's package name.
func (l *BunLock) workspaceKey(path string, ws BunWorkspace) string {
	if path == "" {
		return ""
	}
	if ws.Name != "" {
		return ws.Name
	}
	return path
}

// bunScopeRank orders scopes so a package reachable as production is never
// reported as development because a dev path reached it first.
var bunScopeRank = map[string]int{ScopeProduction: 0, ScopePeer: 1, ScopeOptional: 2, ScopeDevelopment: 3}

// parseBunLockScoped emits every registry package in a bun.lock. A package a
// workspace declares (any workspace: the lockfile of a monorepo is the only lock
// its members have) is direct; the scope is the strongest of the paths that
// reach it, walking each workspace's declared maps through the lock's own
// dependency edges. Workspace, git, tarball, file and link entries are not
// registry releases and are not emitted.
func parseBunLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	lock, err := ParseBunLock(data)
	if err != nil {
		return nil, err
	}

	scope := map[string]string{} // packages key → strongest scope seen
	direct := map[string]bool{}
	type item struct{ key, scope string }
	var queue []item
	visit := func(p BunLockPackage, s string) {
		if prev, ok := scope[p.Key]; ok && bunScopeRank[prev] <= bunScopeRank[s] {
			return
		}
		scope[p.Key] = s
		queue = append(queue, item{p.Key, s})
	}

	wsPaths := make([]string, 0, len(lock.Workspaces))
	for path := range lock.Workspaces {
		wsPaths = append(wsPaths, path)
	}
	sort.Strings(wsPaths)
	for _, path := range wsPaths {
		ws := lock.Workspaces[path]
		parent := lock.workspaceKey(path, ws)
		for _, m := range []struct {
			deps  map[string]string
			scope string
		}{
			{ws.Dependencies, ScopeProduction},
			{ws.PeerDependencies, ScopePeer},
			{ws.OptionalDependencies, ScopeOptional},
			{ws.DevDependencies, ScopeDevelopment},
		} {
			for _, dep := range sortedKeys(m.deps) {
				p, ok := lock.Resolve(parent, dep)
				if !ok {
					continue
				}
				direct[p.Key] = true
				visit(p, m.scope)
			}
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if scope[it.key] != it.scope {
			continue // superseded by a stronger path
		}
		p := lock.Packages[it.key]
		if p.Workspace {
			// A workspace pulled in by another workspace contributes its own
			// declared maps, already walked above.
			continue
		}
		for _, m := range []struct {
			deps  map[string]string
			scope string
		}{
			{p.Dependencies, it.scope},
			{p.PeerDependencies, it.scope},
			{p.OptionalDependencies, weakerScope(it.scope, ScopeOptional)},
		} {
			for _, dep := range sortedKeys(m.deps) {
				if child, ok := lock.Resolve(it.key, dep); ok {
					visit(child, m.scope)
				}
			}
		}
	}

	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var pkgs []ScopedPackage
	seen := map[string]int{} // name@version → index in pkgs
	for _, key := range keys {
		p := lock.Packages[key]
		if !p.Registry {
			continue
		}
		s, ok := scope[key]
		if !ok {
			// Not reachable from any workspace (a stale entry): keep it, as every
			// other lock parser keeps what the lock lists.
			s = ScopeProduction
		}
		id := p.Name + "@" + p.Version
		if i, dup := seen[id]; dup {
			// The same release installed at two paths: one package, strongest scope.
			if bunScopeRank[s] < bunScopeRank[pkgs[i].Scope] {
				pkgs[i].Scope = s
			}
			pkgs[i].IsDirect = pkgs[i].IsDirect || direct[key]
			continue
		}
		sp := ScopedPackage{Name: p.Name, Version: p.Version, Ecosystem: "npm", Scope: s, SourceFile: filePath, IsDirect: direct[key]}
		if c := normalizeChecksum(p.Integrity); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		seen[id] = len(pkgs)
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

// weakerScope returns whichever of two scopes ranks lower (weaker).
func weakerScope(a, b string) string {
	if bunScopeRank[a] >= bunScopeRank[b] {
		return a
	}
	return b
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stripJSONTrailingCommas removes a comma that is followed (after whitespace)
// by "}" or "]", outside string literals: the one way bun.lock departs from
// JSON. Line comments are stripped too, so a hand-annotated lock still reads.
func stripJSONTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			out = append(out, c)
		case '/':
			if i+1 < len(data) && data[i+1] == '/' {
				for i < len(data) && data[i] != '\n' {
					i++
				}
				if i < len(data) {
					out = append(out, '\n')
				}
				continue
			}
			out = append(out, c)
		case ',':
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
