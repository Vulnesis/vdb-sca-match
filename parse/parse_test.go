package parse

import "testing"

// TestParseManifest_CoreFormats exercises the byte-based dispatcher across a
// representative set of ecosystems to confirm the shared parser resolves
// name/version/ecosystem the same way the CLI relies on.
func TestParseManifest_CoreFormats(t *testing.T) {
	cases := []struct {
		name         string
		manifestType string
		data         string
		wantName     string
		wantVersion  string
		wantEco      string
	}{
		{
			name:         "package-lock v3",
			manifestType: "package-lock.json",
			data:         `{"packages":{"":{},"node_modules/lodash":{"version":"4.17.21"}}}`,
			wantName:     "lodash", wantVersion: "4.17.21", wantEco: "npm",
		},
		{
			name:         "requirements.txt",
			manifestType: "requirements.txt",
			data:         "requests==2.31.0\n",
			wantName:     "requests", wantVersion: "2.31.0", wantEco: "pypi",
		},
		{
			name:         "go.sum",
			manifestType: "go.sum",
			data:         "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n",
			wantName:     "github.com/pkg/errors", wantVersion: "0.9.1", wantEco: "golang",
		},
		{
			name:         "Cargo.lock",
			manifestType: "Cargo.lock",
			data:         "[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\n",
			wantName:     "serde", wantVersion: "1.0.197", wantEco: "cargo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, err := ParseManifest([]byte(tc.data), tc.manifestType, tc.manifestType)
			if err != nil {
				t.Fatalf("ParseManifest(%s): %v", tc.manifestType, err)
			}
			var found bool
			for _, p := range pkgs {
				if p.Name == tc.wantName {
					found = true
					if p.Version != tc.wantVersion {
						t.Errorf("version = %q, want %q", p.Version, tc.wantVersion)
					}
					if p.Ecosystem != tc.wantEco {
						t.Errorf("ecosystem = %q, want %q", p.Ecosystem, tc.wantEco)
					}
				}
			}
			if !found {
				t.Fatalf("package %q not found in %d parsed packages", tc.wantName, len(pkgs))
			}
		})
	}
}

// TestBuildPurl covers the ecosystem→purl-type map and the scoped-name special
// cases (npm @scope, maven group:artifact).
func TestBuildPurl(t *testing.T) {
	cases := []struct {
		name, version, eco, want string
	}{
		// npm, pypi, golang basics
		{"lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21"},
		{"requests", "2.31.0", "pypi", "pkg:pypi/requests@2.31.0"},
		{"github.com/pkg/errors", "0.9.1", "golang", "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"},
		{"github.com/pkg/errors", "0.9.1", "go", "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"},
		{"github.com/pkg/errors", "0.9.1", "GoLang", "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"},

		// npm scoped and unscoped fall-through
		{"@babel/core", "7.24.0", "npm", "pkg:npm/babel/core@7.24.0"},
		{"@babel", "7.24.0", "npm", "pkg:npm/@babel@7.24.0"},
		{"lodash", "", "npm", "pkg:npm/lodash"},

		// maven group:artifact and plain-name fall-through
		{"org.apache.commons:commons-lang3", "3.14.0", "maven", "pkg:maven/org.apache.commons/commons-lang3@3.14.0"},
		{"org.apache.commons:commons-lang3", "3.14.0", "java", "pkg:maven/org.apache.commons/commons-lang3@3.14.0"},
		{"commons-lang3", "3.14.0", "maven", "pkg:maven/commons-lang3@3.14.0"},

		// remaining alias pairs
		{"serde", "1.0.197", "cargo", "pkg:cargo/serde@1.0.197"},
		{"serde", "1.0.197", "rust", "pkg:cargo/serde@1.0.197"},
		{"rails", "7.1.3", "gem", "pkg:gem/rails@7.1.3"},
		{"rails", "7.1.3", "rubygems", "pkg:gem/rails@7.1.3"},
		{"laravel/framework", "10.0.0", "composer", "pkg:composer/laravel%2Fframework@10.0.0"},
		{"laravel/framework", "10.0.0", "php", "pkg:composer/laravel%2Fframework@10.0.0"},
		{"http", "1.2.0", "pub", "pkg:pub/http@1.2.0"},
		{"http", "1.2.0", "dart", "pkg:pub/http@1.2.0"},
		{"phoenix", "1.7.0", "hex", "pkg:hex/phoenix@1.7.0"},
		{"phoenix", "1.7.0", "elixir", "pkg:hex/phoenix@1.7.0"},
		{"Newtonsoft.Json", "13.0.3", "nuget", "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"Alamofire", "5.9.0", "swift", "pkg:swift/Alamofire@5.9.0"},
		{"nginx-ingress", "1.0.0", "helm", "pkg:helm/nginx-ingress@1.0.0"},
		{"numpy", "1.26.0", "conda", "pkg:conda/numpy@1.26.0"},

		// clojure coordinates are maven purls
		{"clj-time", "0.15.2", "clojars", "pkg:maven/clj-time@0.15.2"},
		{"clj-time", "0.15.2", "clojure", "pkg:maven/clj-time@0.15.2"},

		// an ecosystem with no alias is its own purl type (deb, apk, oci, ...)
		{"unknown-pkg", "1.0.0", "notareco", "pkg:notareco/unknown-pkg@1.0.0"},
		{"openssl", "3.0.13-1~deb12u1", "deb", "pkg:deb/openssl@3.0.13-1~deb12u1"},
		{"musl", "1.2.4-r2", "apk", "pkg:apk/musl@1.2.4-r2"},
		{"actions/checkout", "v4", "github-actions", "pkg:github-actions/actions%2Fcheckout@v4"},

		// only an empty ecosystem yields no purl
		{"unknown-pkg", "1.0.0", "", ""},
	}
	for _, tc := range cases {
		if got := BuildPurl(tc.name, tc.version, tc.eco); got != tc.want {
			t.Errorf("BuildPurl(%q,%q,%q) = %q, want %q", tc.name, tc.version, tc.eco, got, tc.want)
		}
	}
}
