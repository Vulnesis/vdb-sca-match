package parse

import "testing"

// findByName returns the first package with the given name.
func findByName(pkgs []ScopedPackage, name string) (ScopedPackage, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return ScopedPackage{}, false
}

// assertPackages checks the parsed set has exactly the wanted name→version pairs.
func assertPackages(t *testing.T, pkgs []ScopedPackage, want map[string]string) {
	t.Helper()
	if len(pkgs) != len(want) {
		t.Fatalf("parsed %d package(s), want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for name, ver := range want {
		p, ok := findByName(pkgs, name)
		if !ok {
			t.Errorf("package %q not parsed", name)
			continue
		}
		if p.Version != ver {
			t.Errorf("%s version = %q, want %q", name, p.Version, ver)
		}
	}
}

// A WORKSPACE declares its externals with repository rules; only Maven and Go
// coordinates used to be read, so a C++ project's dependencies were all lost.
func TestParseWorkspace_HTTPArchive(t *testing.T) {
	workspace := `workspace(name = "test")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.9/rules_cc-0.0.9.tar.gz"],
    sha256 = "2037875b9a4456dce4a79d112a8ae885bbc4aad968e6587dca6e64f3a0900cdf",
    strip_prefix = "rules_cc-0.0.9",
)

http_archive(
    name = "com_google_absl",
    urls = ["https://github.com/abseil/abseil-cpp/releases/download/20240116.2/abseil-cpp-20240116.2.tar.gz"],
    strip_prefix = "abseil-cpp-20240116.2",
)

http_archive(
    name = "com_github_grpc_grpc",
    urls = ["https://github.com/grpc/grpc/archive/refs/tags/v1.62.1.tar.gz"],
    strip_prefix = "grpc-1.62.1",
)
`
	pkgs, err := ParseManifest([]byte(workspace), "WORKSPACE", "WORKSPACE")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{
		"rules_cc":   "0.0.9",
		"abseil-cpp": "20240116.2",
		"grpc":       "1.62.1",
	})
	absl, _ := findByName(pkgs, "abseil-cpp")
	if absl.Ecosystem != "bazel" || absl.GitHubURL != "abseil/abseil-cpp" {
		t.Errorf("abseil-cpp = %+v, want bazel / abseil/abseil-cpp", absl)
	}
}

// Buck2 build files reference vendored libraries by target label; the label is
// the only dependency identity the file carries.
func TestParseBuck_ThirdPartyLabels(t *testing.T) {
	buck := `cxx_binary(
    name = "main",
    srcs = ["src/main.cpp"],
    deps = [
        "//third-party:abseil",
        "//third-party:fmt",
        "//third-party:glog",
        "//src/lib:internal",
    ],
)
`
	pkgs, err := ParseManifest([]byte(buck), "BUCK2", "BUCK2")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"abseil": "", "fmt": "", "glog": ""})
	if _, ok := findByName(pkgs, "internal"); ok {
		t.Error("first-party target //src/lib:internal reported as a dependency")
	}
}

// hpack's package.yaml is where a stack project declares its dependencies;
// stack.yaml only carries the resolver and the extra-deps overrides.
func TestParseHpack_Dependencies(t *testing.T) {
	pkgYAML := `name: myapp
version: 0.1.0

executables:
  myapp:
    main: Main.hs
    source-dirs: app
    dependencies:
      - base >= 4.7
      - text
      - aeson

tests:
  spec:
    dependencies:
      - hspec
`
	pkgs, err := ParseManifest([]byte(pkgYAML), "package.yaml", "package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"base": "", "text": "", "aeson": "", "hspec": ""})
	base, _ := findByName(pkgs, "base")
	if base.Ecosystem != "hackage" || base.VersionSpec != ">= 4.7" {
		t.Errorf("base = %+v, want hackage / >= 4.7", base)
	}
	if spec, _ := findByName(pkgs, "hspec"); spec.Scope != ScopeTest {
		t.Errorf("hspec scope = %q, want %q", spec.Scope, ScopeTest)
	}
}

// A Conan Python recipe declares requirements in a method, in a class
// attribute, or both.
func TestParseConanfilePy(t *testing.T) {
	recipe := `from conan import ConanFile


class MyappConan(ConanFile):
    name = "myapp"
    tool_requires = "cmake/3.29.0"

    def requirements(self):
        self.requires("boost/1.85.0")
        self.requires("fmt/10.2.1")
        self.test_requires("catch2/3.6.0")
`
	pkgs, err := ParseManifest([]byte(recipe), "conanfile.py", "conanfile.py")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{
		"boost": "1.85.0", "fmt": "10.2.1", "catch2": "3.6.0", "cmake": "3.29.0",
	})
	if p, _ := findByName(pkgs, "catch2"); p.Scope != ScopeTest {
		t.Errorf("catch2 scope = %q, want %q", p.Scope, ScopeTest)
	}
	if p, _ := findByName(pkgs, "cmake"); p.Scope != ScopeDevelopment {
		t.Errorf("cmake scope = %q, want %q", p.Scope, ScopeDevelopment)
	}
}

// Every opam dependency is a package with its own advisories, including the
// compiler and the build system; the version is reported only when the
// constraint pins one exactly.
func TestParseOpam_AllDependencies(t *testing.T) {
	opam := `opam-version: "2.0"
name: "myapp"
depends: [
  "ocaml" {>= "4.14"}
  "dune" {>= "3.0" & build}
  "lwt" {>= "5.7"}
  "yojson" {= "2.1.0"}
  "conf-libssl" {build}
]
`
	pkgs, err := ParseManifest([]byte(opam), "*.opam", "myapp.opam")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{
		"ocaml": "", "dune": "", "lwt": "", "yojson": "2.1.0",
	})
	if lwt, _ := findByName(pkgs, "lwt"); lwt.VersionSpec != `>= "5.7"` {
		t.Errorf("lwt version spec = %q, want %q", lwt.VersionSpec, `>= "5.7"`)
	}
}

// build.zig.zon keys the dependency by name; the URL only carries the release
// tag, so naming from the URL collapsed same-tag dependencies into one.
func TestParseZigZon_NamesAndVersions(t *testing.T) {
	zon := `.{
    .name = "zig-test",
    .version = "0.1.0",
    .dependencies = .{
        .ziglyph = .{
            .url = "https://github.com/ziglibs/ziglyph/archive/refs/tags/v0.2.0.tar.gz",
            .hash = "1220abc",
        },
        .zld = .{
            .url = "https://github.com/ziglibs/zld/archive/refs/tags/v0.2.0.tar.gz",
            .hash = "1220def",
        },
    },
}
`
	pkgs, err := ParseManifest([]byte(zon), "build.zig.zon", "build.zig.zon")
	if err != nil {
		t.Fatal(err)
	}
	assertPackages(t, pkgs, map[string]string{"ziglyph": "0.2.0", "zld": "0.2.0"})
	if z, _ := findByName(pkgs, "ziglyph"); z.GitHubURL != "ziglibs/ziglyph" {
		t.Errorf("ziglyph GitHubURL = %q, want ziglibs/ziglyph", z.GitHubURL)
	}
}

// A shard.yml version is a quoted range; the quotes and the operator are not
// part of the version.
func TestParseShardYAML_VersionSpec(t *testing.T) {
	shard := `name: app
dependencies:
  kemal:
    github: kemalcr/kemal
    version: "~> 1.4.0"
`
	pkgs, err := ParseManifest([]byte(shard), "shard.yml", "shard.yml")
	if err != nil {
		t.Fatal(err)
	}
	kemal, ok := findByName(pkgs, "kemal")
	if !ok {
		t.Fatalf("kemal not parsed: %+v", pkgs)
	}
	if kemal.Version != "1.4.0" {
		t.Errorf("version = %q, want 1.4.0", kemal.Version)
	}
	if kemal.VersionSpec != "~> 1.4.0" {
		t.Errorf("version spec = %q, want ~> 1.4.0", kemal.VersionSpec)
	}
}

func TestCleanLocalVersion(t *testing.T) {
	cases := map[string]string{
		`"~> 1.4.0"`: "1.4.0",
		">= 2.3":     "2.3",
		"^1.0.0":     "1.0.0",
		"==3.1":      "3.1",
		"v1.2.3":     "1.2.3",
		"1.0.0":      "1.0.0",
	}
	for in, want := range cases {
		if got := cleanLocalVersion(in); got != want {
			t.Errorf("cleanLocalVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
