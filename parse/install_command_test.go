package parse

import "testing"

func TestParseInstallCommandPackages(t *testing.T) {
	pkgs := ParseInstallCommandPackages(
		`apt-get update && apt-get install -y curl openssl=3.0.2 && python -m pip install requests==2.32.0 && dotnet add package Newtonsoft.Json --version 13.0.3`,
		"ci.yml",
		InstallCommandOptions{},
	)
	want := map[string]string{
		"deb:curl":              "",
		"deb:openssl":           "3.0.2",
		"pypi:requests":         "2.32.0",
		"nuget:Newtonsoft.Json": "13.0.3",
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Ecosystem+":"+p.Name] = p.Version
		if p.SourceType != SourceTypeCommand {
			t.Fatalf("SourceType=%q, want %q", p.SourceType, SourceTypeCommand)
		}
	}
	for k, version := range want {
		if got[k] != version {
			t.Fatalf("%s version=%q, want %q (all: %#v)", k, got[k], version, pkgs)
		}
	}
}

func TestParseCIFileScoped(t *testing.T) {
	data := []byte(`stages:
  - build
build:
  script:
    - apk add --no-cache jq
    - npm install left-pad@1.3.0
`)
	pkgs, err := ParseManifest(data, "ci-pipeline", ".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Ecosystem+":"+p.Name+"@"+p.Version] = true
	}
	for _, key := range []string{"apk:jq@", "npm:left-pad@1.3.0"} {
		if !got[key] {
			t.Fatalf("missing %s in %#v", key, pkgs)
		}
	}
}
