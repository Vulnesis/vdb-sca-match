package parse

import "testing"

// TestParsePEP508 applies the documented rules from parsePEP508's comment:
// marker stripping, extras stripping, one case per supported operator, bare
// names, multi-clause versions, and non-requirement input returning ok=false.
func TestParsePEP508(t *testing.T) {
	cases := []struct {
		name            string
		in              string
		wantName        string
		wantVersion     string
		wantVersionSpec string
		wantOK          bool
	}{
		{"bare name", "requests", "requests", "", "", true},
		{"exact equal", "wheel===0.42.0", "wheel", "0.42.0", "===0.42.0", true},
		{"equal", "requests==2.31.0", "requests", "2.31.0", "==2.31.0", true},
		{"greater equal", "pydantic>=1.10", "pydantic", "1.10", ">=1.10", true},
		{"less equal", "pydantic<=2.0", "pydantic", "2.0", "<=2.0", true},
		{"compatible release", "requests~=2.31.0", "requests", "2.31.0", "~=2.31.0", true},
		{"not equal", "numpy!=1.23", "numpy", "1.23", "!=1.23", true},
		{"greater", "django>3.0", "django", "3.0", ">3.0", true},
		{"less", "django<4.0", "django", "4.0", "<4.0", true},
		{"multi clause", "requests>=1.0,<2.0", "requests", "1.0", ">=1.0,<2.0", true},
		{"extras stripped", "requests[security]>=2.0", "requests", "2.0", ">=2.0", true},
		{"markers stripped", "requests>=2.0 ; python_version>='3.8'", "requests", "2.0", ">=2.0", true},
		{"extras and markers", "PyYAML[yaml]>=6.0 ; python_version>='3.8'", "PyYAML", "6.0", ">=6.0", true},
		{"empty", "", "", "", "", false},
		{"comment", "# comment", "", "", "", false},
		{"markers only", "; python_version>='3.8'", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotVersion, gotSpec, gotOK := parsePEP508(tc.in)
			if gotName != tc.wantName || gotVersion != tc.wantVersion || gotSpec != tc.wantVersionSpec || gotOK != tc.wantOK {
				t.Errorf("parsePEP508(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
					tc.in, gotName, gotVersion, gotSpec, gotOK,
					tc.wantName, tc.wantVersion, tc.wantVersionSpec, tc.wantOK)
			}
		})
	}
}

// TestCleanReqVersion asserts the documented behaviour: return the first token
// from a multi-clause version string, splitting on comma or space. The operator
// is stripped by parsePEP508 before this helper runs.
func TestCleanReqVersion(t *testing.T) {
	cases := map[string]string{
		"1.0,<2.0": "1.0",
		"1.0 <2.0": "1.0",
		"1.2.3":    "1.2.3",
		"  1.2.3 ": "1.2.3",
	}
	for in, want := range cases {
		if got := cleanReqVersion(in); got != want {
			t.Errorf("cleanReqVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsRequirementsInclude asserts the exact tokens and prefixes recognised
// as requirement/constraint file includes.
func TestIsRequirementsInclude(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"-r", true},
		{"-c", true},
		{"-r requirements.in", true},
		{"-c constraints.txt", true},
		{"--requirement", true},
		{"--requirement=requirements.in", true},
		{"--constraint", true},
		{"--constraint=constraints.txt", true},
		{"  -c extras.txt  ", true},
		{"pkg", false},
		{"-e", false},
	}
	for _, tc := range cases {
		if got := isRequirementsInclude(tc.in); got != tc.want {
			t.Errorf("isRequirementsInclude(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestEditableEggName asserts the documented extraction of the #egg= name from
// editable/VCS requirements, with termination on space, tab or ampersand.
func TestEditableEggName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"-e git+https://host/repo.git#egg=name", "name"},
		{"-e git+https://host/repo.git#egg=name&subdirectory=src", "name"},
		{"-e git+ssh://host/repo.git#egg=pkg-name", "pkg-name"},
		{"-e git+https://host/repo#egg=pkg extra", "pkg"},
		{"-e git+https://host/repo#egg=pkg\textra", "pkg"},
		{"-e git+https://host/repo.git", ""},
		{"no egg here", ""},
	}
	for _, tc := range cases {
		if got := editableEggName(tc.in); got != tc.want {
			t.Errorf("editableEggName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
