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
		"pkg:alpm/arch/vim@9.0.1224-1?arch=x86_64":                        "arch",
		"pkg:alpm/archlinux/openssl@3.4.0-1":                              "arch",
		"pkg:alpm/cachyos/zlib@1:1.3.1-2?arch=x86_64_v3&distro=cachyos":   "arch",
		"pkg:alpm/manjaro/curl@8.11.0-1":                                  "arch",
		"pkg:alpm/aur/yay@12.4.2-1":                                       "",
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
	for _, eco := range []string{"alpine", "debian", "ubuntu", "redhat", "rocky", "almalinux", "amazon", "suse", "fedora", "wolfi", "arch"} {
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
		{"arch", "1:2.3.4-2", "2.3.4"},
		{"arch", "6.12.1.arch1-1", "6.12.1.arch1"},
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

func TestSameBranch(t *testing.T) {
	cases := []struct {
		distro, installed, rng string
		want                   bool
	}{
		{"alpine", "3.1.8-r0", "<3.3.3-r0", false},
		{"alpine", "3.1.8-r0", "<3.1.9-r0", true},
		{"debian", "1:2.41-12+deb13u4", "<2.41-12+deb13u5", true},
		{"debian", "1:2.41-12+deb13u4", ">=0, <2.36-9+deb12u7", false},
		{"alpine", "1.36.1-r7", "*", true},
		{"alpine", "5-r0", "<6-r0", true},
	}
	for _, c := range cases {
		if got := sameBranch(c.distro, c.installed, c.rng); got != c.want {
			t.Errorf("sameBranch(%s, %s, %q) = %v, want %v", c.distro, c.installed, c.rng, got, c.want)
		}
	}
}

func TestSingleStreamDistrosAreNotBranchChecked(t *testing.T) {
	// Arch is rolling and Amazon Linux rows are tagged by release: an install on
	// an older upstream branch than the fix is below the fix, not "another
	// branch's fix". The same ranges on Alpine stay branch-scoped.
	if !singleStream("arch") || !singleStream("amazon") {
		t.Fatal("arch and amazon are single-stream")
	}
	for _, d := range []string{"alpine", "debian", "ubuntu", "redhat", "rocky", "suse", "wolfi", ""} {
		if singleStream(d) {
			t.Errorf("%q must keep the branch check", d)
		}
	}
	if sameBranch("amazon", "8.0.1-1.amzn2023.0.1", "<8.5.0-1.amzn2023.0.1") {
		t.Fatal("sameBranch itself still sees two branches; MatchOSPackage must not call it for amazon")
	}
}

func TestEpochVersion(t *testing.T) {
	cases := []struct{ purl, in, want string }{
		{"pkg:rpm/amazon/openssl-libs@3.0.8-1.amzn2023.0.1?arch=aarch64&distro=amazon-2023&epoch=1&upstream=openssl", "3.0.8-1.amzn2023.0.1", "1:3.0.8-1.amzn2023.0.1"},
		{"pkg:rpm/amazon/bash@5.2.15-3.amzn2023.0.1?arch=aarch64&distro=amazon-2023", "5.2.15-3.amzn2023.0.1", "5.2.15-3.amzn2023.0.1"},
		{"pkg:rpm/amazon/x@1-1?epoch=0&distro=amazon-2023", "1-1", "1-1"},
		{"pkg:rpm/amazon/x@1:1-1?epoch=1&distro=amazon-2023", "1:1-1", "1:1-1"},
		{"pkg:rpm/amazon/x@1-1?epoch=junk&distro=amazon-2023", "1-1", "1-1"},
		// Other rpm distributions keep their version: their rows are not written with an epoch.
		{"pkg:rpm/redhat/openssl@3.0.7-24.el9?epoch=1&distro=rhel-9", "3.0.7-24.el9", "3.0.7-24.el9"},
		{"pkg:rpm/amazon/x?epoch=1&distro=amazon-2023", "", ""},
		{"not a purl", "1.0", "1.0"},
	}
	for _, c := range cases {
		if got := EpochVersion(c.purl, c.in); got != c.want {
			t.Errorf("EpochVersion(%q, %q) = %q, want %q", c.purl, c.in, got, c.want)
		}
	}
}
