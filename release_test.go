package match

import (
	"strings"
	"testing"
)

func TestDistroRelease(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:deb/debian/tar@1.34+dfsg-1.2+deb12u1?arch=amd64&distro=debian-12": "debian:12",
		"pkg:deb/debian/libc6@2.36-9?distro=debian-12.5":                       "debian:12",
		"pkg:deb/debian/dash@0.5.12-2?distro=bookworm":                         "debian:12",
		"pkg:deb/ubuntu/perl-base@5.34.0-3ubuntu1.9?distro=ubuntu-22.04":       "ubuntu:22.04",
		"pkg:apk/alpine/busybox@1.36.1-r7?distro=alpine-3.18.4":                "alpine:v3.18",
		"pkg:apk/alpine/busybox@1.36.1-r7?distro=3.18.4":                       "alpine:v3.18",
		"pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9":                           "",
		"pkg:deb/debian/tar@1.34":                                              "",
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
