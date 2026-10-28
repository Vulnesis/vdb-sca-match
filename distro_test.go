package match

import "testing"

func TestDistroEcosystem(t *testing.T) {
	cases := map[string]string{
		"pkg:apk/alpine/busybox@1.36.1-r7?arch=x86_64&distro=alpine-3.18": "alpine",
		"pkg:deb/debian/libc6@2.36-9+deb12u4?distro=debian-12":            "debian",
		"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?distro=ubuntu-22.04":    "ubuntu",
		"pkg:rpm/amazonlinux/runc@1.1.7-1.amzn2?distro=amzn-2":            "amazon",
		"pkg:rpm/redhat/openssl@3.0.7-27.el9?distro=rhel-9.4":             "redhat",
		"pkg:rpm/rocky/bash@5.1.8-9.el9":                                  "rocky",
		"pkg:apk/wolfi/glibc@2.40-r3":                                     "wolfi",
		"pkg:deb/kali/foo@1":                                              "",
		"pkg:npm/lodash@4.17.21":                                          "",
		"pkg:generic/amazon/ec2?arn=x":                                    "",
		"not a purl":                                                      "",
	}
	for purl, want := range cases {
		if got := DistroEcosystem(purl); got != want {
			t.Errorf("DistroEcosystem(%q) = %q, want %q", purl, got, want)
		}
	}
	// Every distro it names has advisory evidence to restrict on.
	for _, eco := range []string{"alpine", "debian", "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora", "wolfi"} {
		if _, urls, vendors, ok := EcosystemEvidence(eco); !ok || (len(urls) == 0 && len(vendors) == 0) {
			t.Errorf("%s has no ecosystem evidence", eco)
		}
	}
}

func TestUpstreamVersion(t *testing.T) {
	cases := []struct{ distro, in, want string }{
		{"alpine", "1.36.1-r7", "1.36.1"},
		{"debian", "1:9.2p1-2+deb12u2", "9.2p1"},
		{"debian", "1.35+dfsg-3.1", "1.35"},
		{"debian", "5.6.1+really5.4.5-1", "5.4.5"},
		{"ubuntu", "3.0.2-0ubuntu1.15", "3.0.2"},
		{"amazon", "1.1.7-1.amzn2", "1.1.7"},
		{"debian", "3.152", "3.152"},
		{"", "1.2.3-4", "1.2.3-4"},
	}
	for _, c := range cases {
		if got := UpstreamVersion(c.distro, c.in); got != c.want {
			t.Errorf("UpstreamVersion(%s, %s) = %s, want %s", c.distro, c.in, got, c.want)
		}
	}
}

func TestDistroSource(t *testing.T) {
	if got := DistroSource("pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=debian-13&upstream=glibc"); got != "glibc" {
		t.Fatalf("got %q", got)
	}
	if DistroSource("pkg:deb/debian/tar@1.35") != "" {
		t.Fatal("no qualifier, no source")
	}
}
