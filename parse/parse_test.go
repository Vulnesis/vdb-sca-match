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
		{"lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21"},
		{"@babel/core", "7.24.0", "npm", "pkg:npm/babel/core@7.24.0"},
		{"org.apache.commons:commons-lang3", "3.14.0", "maven", "pkg:maven/org.apache.commons/commons-lang3@3.14.0"},
		{"requests", "2.31.0", "pypi", "pkg:pypi/requests@2.31.0"},
		{"github.com/pkg/errors", "0.9.1", "golang", "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"},
	}
	for _, tc := range cases {
		if got := BuildPurl(tc.name, tc.version, tc.eco); got != tc.want {
			t.Errorf("BuildPurl(%q,%q,%q) = %q, want %q", tc.name, tc.version, tc.eco, got, tc.want)
		}
	}
}
