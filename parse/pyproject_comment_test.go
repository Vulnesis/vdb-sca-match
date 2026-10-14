package parse

import "testing"

// A comment after a dependency string used to leak its closing quote into the
// version: "apache-airflow-providers-fab>=3.6.0", # set from MIN_VERSION_OVERRIDE
// parsed as version `3.6.0"`, which no release matches and no comparison can read.
func TestPyprojectDependencyWithTrailingCommentKeepsACleanVersion(t *testing.T) {
	src := []byte(`[project]
name = "x"
dependencies = [
    "apache-airflow-providers-fab>=3.6.0", # Set from MIN_VERSION_OVERRIDE
    'requests==2.31.0', # pinned
    "plain>=1.0",
]
`)
	pkgs, err := parsePyprojectTOMLScoped(src, "pyproject.toml")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"apache-airflow-providers-fab": "3.6.0", "requests": "2.31.0", "plain": "1.0"}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: version %q, want %q (all: %v)", n, got[n], v, got)
		}
	}
}

// A manifest that declares a range must say so. Without the raw spec a lockfile gate
// reads the package as pinned: mix.exs `{:mint, "~> 1.4"}` was scanned as mint 1.4
// (a vulnerable release) while mix.lock pinned 1.9.3.
func TestManifestRangesKeepTheirRawSpec(t *testing.T) {
	mix, err := parseMixScoped([]byte("  {:mint, \"~> 1.4\", only: :test},\n"), "mix.exs")
	if err != nil || len(mix) != 1 || mix[0].VersionSpec != "~> 1.4" {
		t.Fatalf("mix.exs spec = %+v err=%v", mix, err)
	}
	pub, err := parsePubspecYAMLScoped([]byte("dependencies:\n  http: ^1.2.0\n"), "pubspec.yaml")
	if err != nil || len(pub) != 1 || pub[0].VersionSpec != "^1.2.0" {
		t.Fatalf("pubspec.yaml spec = %+v err=%v", pub, err)
	}
}

// With central package management the project files carry no version; the pins live in
// Directory.Packages.props. Jellyfin scanned to zero packages without reading it.
func TestDirectoryPackagesPropsYieldsThePinnedVersions(t *testing.T) {
	src := []byte(`<Project>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="4.3.0" />
    <PackageVersion Include="Newtonsoft.Json" Version="$(NewtonsoftVersion)" />
    <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.2.0-beta.556" />
  </ItemGroup>
</Project>`)
	pkgs, err := ParseManifest(src, "Directory.Packages.props", "Directory.Packages.props")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["Serilog"] != "4.3.0" || got["StyleCop.Analyzers"] != "1.2.0-beta.556" {
		t.Fatalf("pins not read: %v", got)
	}
	if got["Newtonsoft.Json"] != "$(NewtonsoftVersion)" {
		t.Errorf("an MSBuild property is kept verbatim, got %q", got["Newtonsoft.Json"])
	}
}
