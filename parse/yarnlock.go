package parse

import (
	"bufio"
	"strings"
)

// yarnBlock is one entry of a yarn.lock: its header specifiers and the fields
// the parser reads. Classic (v1) and Berry (v2+) differ in field syntax
// (`version "1.2.3"` vs `version: 1.2.3`) and in field order: Berry writes the
// checksum after the version, so a block is only complete at the next header.
type yarnBlock struct {
	specs      []string
	version    string
	resolution string // Berry: "name@npm:1.2.3", "name@workspace:path", "name@patch:..."
	resolved   string // Classic: the tarball URL
	integrity  string
	deps       []string // dependency names (Berry workspace blocks: the member's declared deps)
}

// yarnSpecName returns the package name of a header specifier, and the
// requested range: "@s/p@npm:^1" → ("@s/p", "npm:^1").
func yarnSpecName(spec string) (name, rng string) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.Index(spec[start:], "@")
	if i < 0 {
		return spec, ""
	}
	i += start
	return spec[:i], spec[i+1:]
}

// yarnNonRegistry reports whether a range or resolution names a workspace,
// path, link or VCS source rather than a registry release.
func yarnNonRegistry(r string) bool {
	for _, p := range []string{"workspace:", "link:", "portal:", "file:", "exec:", "git+", "git:", "github:", "http:", "https:"} {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}

// name returns the package a block installs and whether it is a registry
// release. A Berry resolution is authoritative (it names the real package of an
// npm: alias); Classic has only the header, where an alias is "alias@npm:real@^1".
func (b yarnBlock) name() (string, bool) {
	if b.resolution != "" {
		name, res := yarnSpecName(b.resolution)
		switch {
		case strings.HasPrefix(res, "npm:"), strings.HasPrefix(res, "patch:"):
			return name, true
		default:
			return name, false // workspace:, link:, portal:, file:, a git or tarball URL
		}
	}
	if len(b.specs) == 0 {
		return "", false
	}
	name, rng := yarnSpecName(b.specs[0])
	if strings.HasPrefix(rng, "npm:") {
		if real, _ := yarnSpecName(strings.TrimPrefix(rng, "npm:")); strings.Contains(strings.TrimPrefix(rng, "npm:"), "@") && real != "" {
			name = real
		}
	}
	for _, s := range b.specs {
		if _, r := yarnSpecName(s); yarnNonRegistry(r) {
			return name, false
		}
	}
	return name, true
}

func parseYarnLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// yarn.lock records no dev/prod scope, so every package is production; the
	// scope of a direct dependency comes from package.json. Berry lists each
	// workspace as a block whose dependencies are what that member declares, so
	// those names are direct; Classic records no workspaces and leaves IsDirect
	// to package.json.
	var blocks []yarnBlock
	var cur *yarnBlock
	inDeps := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			if strings.HasPrefix(trimmed, "__metadata") || !strings.Contains(trimmed, "@") {
				cur = nil
				continue
			}
			header := strings.TrimSuffix(trimmed, ":")
			blk := yarnBlock{}
			for _, s := range strings.Split(header, ",") {
				s = strings.Trim(strings.TrimSpace(s), `"`)
				if s != "" {
					blk.specs = append(blk.specs, s)
				}
			}
			blocks = append(blocks, blk)
			cur = &blocks[len(blocks)-1]
			inDeps = false
			continue
		}
		if cur == nil {
			continue
		}
		if indent <= 2 {
			inDeps = false
			key, val := trimmed, ""
			if i := strings.IndexAny(trimmed, ": "); i > 0 {
				key = trimmed[:i]
				val = strings.TrimSpace(strings.TrimPrefix(trimmed[i:], ":"))
			}
			val = strings.Trim(val, `"'`)
			switch key {
			case "version":
				cur.version = val
			case "resolution":
				cur.resolution = val
			case "resolved":
				cur.resolved = val
			case "integrity", "checksum":
				cur.integrity = val
			case "dependencies", "devDependencies", "optionalDependencies", "peerDependencies":
				inDeps = true
			}
			continue
		}
		if inDeps {
			dep := trimmed
			if i := strings.IndexAny(dep, ": "); i > 0 {
				dep = dep[:i]
			}
			// Classic quotes a scoped key ("@s/p" "^1"); Berry writes "@s/p": npm:^1.
			cur.deps = append(cur.deps, strings.Trim(dep, `"`))
		}
	}

	direct := map[string]bool{}
	for _, b := range blocks {
		if b.resolution != "" && strings.Contains(b.resolution, "@workspace:") {
			for _, d := range b.deps {
				direct[d] = true
			}
		}
	}

	var pkgs []ScopedPackage
	seen := make(map[string]bool)
	for _, b := range blocks {
		name, ok := b.name()
		if !ok || name == "" || !registryVersion(b.version) {
			continue
		}
		key := name + "@" + b.version
		if seen[key] {
			continue
		}
		seen[key] = true
		sp := ScopedPackage{Name: name, Version: b.version, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath, IsDirect: direct[name]}
		if c := normalizeChecksum(b.integrity); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}
