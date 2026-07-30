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

// TestParseCIFileScopedMultiDocument covers Tekton/Argo-style streams, where the
// pipeline that installs packages is not the first YAML document in the file.
func TestParseCIFileScopedMultiDocument(t *testing.T) {
	data := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
---
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: deps
      image: alpine
      script: |
        apk add --no-cache jq
        pip install requests==2.32.0
`)
	pkgs, err := ParseManifest(data, "ci-pipeline", "tekton/task.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Ecosystem+":"+p.Name+"@"+p.Version] = true
	}
	for _, key := range []string{"apk:jq@", "pypi:requests@2.32.0"} {
		if !got[key] {
			t.Fatalf("missing %s in %#v", key, pkgs)
		}
	}
}

// TestParseCIFileScopedVendorKeys pins the per-vendor "run this" keys: a missed
// key silently drops every package the pipeline installs.
func TestParseCIFileScopedVendorKeys(t *testing.T) {
	cases := map[string]string{
		"travis before_install": "before_install:\n  - gem install bundler -v 2.5.6\n",
		"drone commands":        "steps:\n  - name: build\n    commands:\n      - apt-get install -y ripgrep\n",
		"azure pwsh":            "steps:\n  - pwsh: choco install gh\n",
		"bitrise content":       "workflows:\n  ci:\n    steps:\n      - script:\n          inputs:\n            - content: brew install jq\n",
		"taskfile cmds":         "tasks:\n  deps:\n    cmds:\n      - cargo install just\n",
		"cloud-init runcmd":     "#cloud-config\nruncmd:\n  - yum install -y nginx\n",
		"devcontainer":          `{"postCreateCommand": "pnpm add zod@3.23.8"}`,
		"argo args":             "spec:\n  templates:\n    - container:\n        args: [\"pip install flask==3.0.3\"]\n",
	}
	for name, body := range cases {
		pkgs, err := ParseManifest([]byte(body), "ci-pipeline", "pipeline.yml")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(pkgs) == 0 {
			t.Errorf("%s: no packages extracted from %q", name, body)
		}
	}
}

// TestParseCIFileScopedNonYAMLDSLs covers the vendor DSLs that are not YAML:
// Kotlin/Groovy pipeline scripts and TOML build configs fall back to
// line-oriented shell parsing, while JSON configs parse as YAML.
func TestParseCIFileScopedNonYAMLDSLs(t *testing.T) {
	cases := map[string]string{
		"teamcity kotlin": "script { scriptContent = \"apt-get install -y curl\" }\n",
		"jenkins groovy":  "sh 'pip install requests==2.32.0'\n",
		"netlify toml":    "[build]\n  command = \"npm install -g typescript\"\n",
		"vercel json":     `{"installCommand": "pnpm add zod@3.23.8"}`,
	}
	for name, body := range cases {
		pkgs, err := ParseManifest([]byte(body), "ci-pipeline", "pipeline")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(pkgs) == 0 {
			t.Errorf("%s: no packages extracted from %q", name, body)
		}
	}
}
