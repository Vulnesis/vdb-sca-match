package match

import (
	"strings"
	"testing"
)

func TestDistroRelease(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:deb/debian/tar@1.34+dfsg-1.2+deb12u1?arch=amd64&distro=debian-12":             "debian:12",
		"pkg:deb/debian/libc6@2.36-9?distro=debian-12.5":                                   "debian:12",
		"pkg:deb/debian/dash@0.5.12-2?distro=bookworm":                                     "debian:12",
		"pkg:deb/ubuntu/perl-base@5.34.0-3ubuntu1.9?distro=ubuntu-22.04":                   "ubuntu:22.04",
		"pkg:apk/alpine/busybox@1.36.1-r7?distro=alpine-3.18.4":                            "alpine:v3.18",
		"pkg:apk/alpine/busybox@1.36.1-r7?distro=3.18.4":                                   "alpine:v3.18",
		"pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9":                                       "",
		"pkg:rpm/amazon/openssl-libs@3.0.8-1.amzn2023.0.1?arch=aarch64&distro=amazon-2023": "amazon:2023",
		"pkg:rpm/amazon/bash@4.2-1.amzn2?distro=amzn-2":                                    "amazon:2",
		"pkg:rpm/amazon/bash@4.2-1?distro=amazonlinux-2.0":                                 "amazon:2",
		"pkg:rpm/amazon/bash@5.2-1.amzn2023?distro=amzn2023":                               "amazon:2023",
		"pkg:rpm/amazon/bash@5.2-1":                                                        "",
		"pkg:alpm/arch/vim@9.0.1224-1?arch=x86_64":                                         "",
		"pkg:deb/debian/tar@1.34":                                                          "",
	} {
		if got := DistroRelease(purl); got != want {
			t.Errorf("DistroRelease(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestReleaseClauseDefersUntaggedRowsToTheRelease(t *testing.T) {
	c := releaseClause("a", 4)
	for _, want := range []string{
		`POSITION(':' IN COALESCE(a."vendor", '')) = 0`,
		`$4 || ':%'`,
		`UPPER(split_part($4, ':', 1)) || '-' || a."cveId"`,
		`= LOWER($1)`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("clause lacks %s: %s", want, c)
		}
	}
}

func TestRegistryEcosystem(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:npm/tar@6.2.1":                        "npm",
		"pkg:golang/github.com/x/y@v1.0.0":         "go",
		"pkg:pypi/requests@2.31.0":                 "pypi",
		"pkg:deb/debian/tar@1.34?distro=debian-12": "",
		"pkg:apk/alpine/busybox@1.36.1-r7":         "",
		"pkg:generic/openssl@3.0.0":                "",
		"not a purl":                               "",
	} {
		if got := RegistryEcosystem(purl); got != want {
			t.Errorf("RegistryEcosystem(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestGoModuleMatchExprIsAnIndexableRange(t *testing.T) {
	e := goModuleMatchExpr("a")
	for _, want := range []string{`= LOWER($1)`, `~>=~ (LOWER($1) || '/')`, `~<~ (LOWER($1) || '0')`} {
		if !strings.Contains(e, want) {
			t.Errorf("expr lacks %s: %s", want, e)
		}
	}
	if strings.Contains(e, "LIKE") {
		t.Errorf("a LIKE built from $1 cannot use the btree in a generic plan: %s", e)
	}
}

func TestNativeClauseReadsTheRegistrySetOnce(t *testing.T) {
	c := nativeClause("a")
	if !strings.Contains(c, `WHERE filed.id = a."cveId"`) {
		t.Errorf("the candidate should meet the filed set by one equality: %s", c)
	}
	if strings.Contains(registryFiled, `a."cveId"`) || strings.Contains(c, `"primaryCveId" = a."cveId"`) || strings.Contains(c, `"aliasCveId" = a."cveId"`) {
		t.Errorf("the filed set must not depend on the candidate row, or Postgres reruns it per row: %s", c)
	}
	for _, want := range []string{`al."aliasCveId" = f.id`, `al."primaryCveId" = f.id`, `= ANY($3::text[])`, `= ANY($4::text[])`} {
		if !strings.Contains(c, want) {
			t.Errorf("clause lacks %s: %s", want, c)
		}
	}
}
