package parse

import (
	"strings"
	"testing"
)

// Field-level checks for the npm manifest and lock parsers: the existing
// lockfile tests in jslock_test.go pin which packages are read; these pin what
// each record carries (scope, raw spec, cleaned version, directness, checksum).

// package.json: each dependency map has its own scope, every entry is direct,
// Version is the cleaned spec and VersionSpec keeps the raw one.
func TestParsePackageJSONScoped_ScopesAndSpecs(t *testing.T) {
	const manifest = `{
  "dependencies":         {"express": "^4.21.0", "@scope/pkg": "1.2.3"},
  "devDependencies":      {"jest": "~29.7.0"},
  "peerDependencies":     {"react": ">=18.0.0"},
  "optionalDependencies": {"fsevents": "2.3.3"}
}`
	pkgs, err := parsePackageJSONScoped([]byte(manifest), "web/package.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, version, spec, scope string
	}{
		{"express", "4.21.0", "^4.21.0", ScopeProduction},
		{"@scope/pkg", "1.2.3", "1.2.3", ScopeProduction},
		{"jest", "29.7.0", "~29.7.0", ScopeDevelopment},
		{"react", "18.0.0", ">=18.0.0", ScopePeer},
		{"fsevents", "2.3.3", "2.3.3", ScopeOptional},
	}
	if len(pkgs) != len(cases) {
		t.Fatalf("parsed %d package(s), want %d: %+v", len(pkgs), len(cases), pkgs)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := findByName(pkgs, tc.name)
			if !ok {
				t.Fatalf("%s not parsed", tc.name)
			}
			if p.Version != tc.version {
				t.Errorf("Version = %q, want %q", p.Version, tc.version)
			}
			if p.VersionSpec != tc.spec {
				t.Errorf("VersionSpec = %q, want %q", p.VersionSpec, tc.spec)
			}
			if p.Scope != tc.scope {
				t.Errorf("Scope = %q, want %q", p.Scope, tc.scope)
			}
			if p.Ecosystem != "npm" {
				t.Errorf("Ecosystem = %q, want npm", p.Ecosystem)
			}
			if !p.IsDirect {
				t.Error("IsDirect = false, want true")
			}
			if p.SourceFile != "web/package.json" {
				t.Errorf("SourceFile = %q, want web/package.json", p.SourceFile)
			}
			if len(p.Checksums) != 0 {
				t.Errorf("a manifest carries no checksums: %+v", p.Checksums)
			}
		})
	}
}

func TestParsePackageJSONScoped_Invalid(t *testing.T) {
	if _, err := parsePackageJSONScoped([]byte(`{"dependencies": `), "package.json"); err == nil {
		t.Error("truncated package.json must be an error")
	}
}

// A package.json with no dependency maps yields nothing, not an error.
func TestParsePackageJSONScoped_NoDependencies(t *testing.T) {
	pkgs, err := parsePackageJSONScoped([]byte(`{"name": "app", "version": "1.0.0"}`), "package.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("packages = %+v, want none", pkgs)
	}
}

// yarn Classic: a scoped header with several specifiers names one package, its
// integrity line becomes a SHA-512 checksum, and the record is a lock entry
// (no VersionSpec).
func TestParseYarnLockScoped_ClassicRecord(t *testing.T) {
	const lock = `# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#abc"
  integrity sha512-AAAA

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
  integrity sha512-BBBB
`
	pkgs, err := parseYarnLockScoped([]byte(lock), "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"@babel/code-frame": "7.12.13", "lodash": "4.17.21"})
	for name, value := range map[string]string{"@babel/code-frame": "AAAA", "lodash": "BBBB"} {
		p, _ := findByName(pkgs, name)
		if len(p.Checksums) != 1 || p.Checksums[0] != (PackageChecksum{"SHA-512", value}) {
			t.Errorf("%s checksums = %+v, want SHA-512 %s", name, p.Checksums, value)
		}
		if p.VersionSpec != "" {
			t.Errorf("%s VersionSpec = %q, want empty for a lock entry", name, p.VersionSpec)
		}
		if p.Ecosystem != "npm" || p.SourceFile != "yarn.lock" {
			t.Errorf("%s ecosystem/source = %q/%q", name, p.Ecosystem, p.SourceFile)
		}
	}
}

// yarn Berry: the unquoted "version:" field and the "checksum:" field are read.
// The checksum is a hex SHA-512; Yarn 4 prefixes it with the cache key
// ("10c0/"), Yarn 2 and 3 write it bare. Both were dropped before.
func TestParseYarnLockScoped_BerryChecksum(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 8)
	for _, tc := range []struct{ name, cacheKey, checksum string }{
		{"yarn4", "10c0", "10c0/" + sha},
		{"yarn3", "8", sha},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock := `__metadata:
  version: 6
  cacheKey: ` + tc.cacheKey + `

"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: ` + tc.checksum + `
  languageName: node
  linkType: hard
`
			pkgs, err := parseYarnLockScoped([]byte(lock), "yarn.lock")
			if err != nil {
				t.Fatal(err)
			}
			assertPackages(t, pkgs, map[string]string{"lodash": "4.17.21"})
			if c := pkgs[0].Checksums; len(c) != 1 || c[0] != (PackageChecksum{"SHA-512", sha}) {
				t.Errorf("Berry checksum = %+v, want SHA-512 %s", c, sha)
			}
		})
	}
}

// A malformed Berry checksum is not reported as a hash.
func TestParseYarnLockScoped_BerryChecksumMalformed(t *testing.T) {
	const lock = `"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/not-a-hash
`
	pkgs, err := parseYarnLockScoped([]byte(lock), "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"lodash": "4.17.21"})
	if c := pkgs[0].Checksums; len(c) != 0 {
		t.Errorf("malformed checksum kept: %+v", c)
	}
}

// pnpm: the integrity under "resolution" is a SHA-512 checksum on the record
// for name@version, and a peer-suffixed key resolves to the bare version.
func TestParsePnpmLockScoped_RecordFields(t *testing.T) {
	const lock = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react-dom:
        specifier: ^18
        version: 18.2.0(react@18.2.0)

packages:

  react-dom@18.2.0:
    resolution: {integrity: sha512-BBBB}

  react@18.2.0:
    resolution: {integrity: sha512-CCCC}

snapshots:

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  react@18.2.0: {}
`
	pkgs, err := parsePnpmLockScoped([]byte(lock), "pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"react-dom": "18.2.0", "react": "18.2.0"})
	for name, value := range map[string]string{"react-dom": "BBBB", "react": "CCCC"} {
		p, _ := findByName(pkgs, name)
		if len(p.Checksums) != 1 || p.Checksums[0] != (PackageChecksum{"SHA-512", value}) {
			t.Errorf("%s checksums = %+v, want SHA-512 %s", name, p.Checksums, value)
		}
		if p.Ecosystem != "npm" || p.SourceFile != "pnpm-lock.yaml" {
			t.Errorf("%s ecosystem/source = %q/%q", name, p.Ecosystem, p.SourceFile)
		}
	}
	if p, _ := findByName(pkgs, "react-dom"); !p.IsDirect {
		t.Error("react-dom is declared by the root importer and must be direct")
	}
	if p, _ := findByName(pkgs, "react"); p.IsDirect {
		t.Error("react is only reached through react-dom and must not be direct")
	}
}
