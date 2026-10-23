package version

import (
	"strings"
)

// ecosystemScheme maps an ecosystem name to the scheme that orders and judges
// the versions of its PACKAGES. The catalogue lists every ecosystem name a
// scheme could be known by, and several are shared with a runtime or product
// scheme (python is PEP 440 for a package and python-runtime for the
// interpreter; go is Go modules and go-toolchain); this table fixes the package
// reading, which is what vulnerability data and safe harbour are keyed on.
// TestEcosystemTable keeps each entry honest against the catalogue.
var ecosystemScheme = map[string]string{
	// language registries
	"npm": "semver", "yarn": "semver", "pnpm": "semver",
	"pypi": "pep440", "pip": "pep440", "python": "pep440", "pep440": "pep440", "uv": "pep440", "poetry": "pep440",
	"go": "go", "golang": "go", "gomod": "go",
	"maven": "maven", "java": "maven", "jvm": "maven", "kotlin": "maven", "scala": "maven", "groovy": "maven",
	"leiningen": "maven", "maven-central": "maven", "sbt": "maven", "coursier": "maven", "mill": "maven",
	"scala-cli": "maven", "bloop": "maven",
	"clojars": "clojars", "clojure": "clojars",
	"gradle": "gradle", "ivy": "gradle", "ant": "gradle",
	"cargo": "cargo", "crates.io": "cargo",
	"nuget":    "nuget",
	"rubygems": "rubygems", "gem": "rubygems", "ruby": "rubygems", "bundler": "rubygems",
	"packagist": "composer", "composer": "composer",
	"pub": "pub", "hex": "hex", "rebar3": "rebar3", "erlang": "rebar3",
	"hackage": "hackage", "ghc": "hackage",
	"cran": "cran", "bioconductor": "bioconductor", "cpan": "cpan",
	"swift": "swift", "swifturl": "swift", "cocoapods": "cocoapods",
	"conan": "conan", "conancenter": "conan", "vcpkg": "vcpkg",
	"helm": "helm", "terraform": "terraform", "julia": "julia", "opam": "opam", "luarocks": "luarocks",
	"conda": "conda", "conda-forge": "conda", "anaconda": "conda", "mamba": "conda", "pixi": "conda",
	"zerover": "zerover", "calver": "calver",

	// operating systems and distributions
	"debian": "debian", "ubuntu": "debian", "kali": "debian", "raspbian": "debian", "raspberry pi os": "debian",
	"linuxmint": "debian", "mint": "debian", "devuan": "debian", "echo": "debian", "pureos": "debian", "tails": "debian",
	"red hat": "rpm", "rhel": "rpm", "redhat": "rpm", "centos": "rpm", "fedora": "rpm", "rocky linux": "rpm",
	"rocky": "rpm", "almalinux": "rpm", "suse": "rpm", "sles": "rpm", "opensuse": "rpm", "amazon": "rpm",
	"amazon linux": "rpm", "oracle": "rpm", "oracle linux": "rpm", "mageia": "rpm", "photon os": "rpm",
	"photon": "rpm", "azure linux": "rpm", "azurelinux": "rpm", "openeuler": "rpm", "tuxcare": "rpm",
	"alpine": "alpine", "alpaquita": "alpine", "bellsoft hardened containers": "alpine", "minimos": "alpine",
	"wolfi": "wolfi", "chainguard": "wolfi", "docker hardened images": "wolfi", "cleanstart": "wolfi",
	"arch": "arch", "archlinux": "arch", "cachyos": "arch", "manjaro": "arch", "endeavouros": "arch", "aur": "arch",
	"homebrew": "homebrew", "brew": "homebrew", "nix": "nix", "nixpkgs": "nix", "nixos": "nix",
	"gentoo": "gentoo", "portage": "gentoo", "bitnami": "bitnami",
	"android": "android", "linux": "linux", "linux-kernel": "linux-kernel", "kernel": "linux-kernel",

	// release channels and registries without a package grammar
	"github-actions": "github-release", "github-release": "github-release", "github": "github-release",
	"git": "git-ref", "gitref": "git-ref", "github-ref": "git-ref", "gitlab-ref": "git-ref", "oss-fuzz": "git-ref",
	"docker": "docker", "oci": "docker", "ghcr": "docker", "quay": "docker", "ecr": "docker",
	"vscode": "vscode", "openvsx": "vscode", "vsce": "vscode", "vscode-marketplace": "vscode",
	"chocolatey": "chocolatey", "choco": "chocolatey", "winget": "winget", "scoop": "scoop",
	"jetbrains": "jetbrains", "jetbrains-plugin": "jetbrains", "chrome": "browser-extension",
	"firefox": "browser-extension", "edge": "browser-extension", "browser-extension": "browser-extension",
	"nodejs": "nodejs", "node": "nodejs", "go-toolchain": "go-toolchain", "rust-toolchain": "rust-toolchain",
	"rustup": "rust-toolchain", "rustc": "rust-toolchain", "python-runtime": "python-runtime", "cpython": "python-runtime",
	"openssl": "openssl", "php": "php", "unity": "unity", "ubuntu-release": "ubuntu", "apple": "apple", "macos": "apple",
	"ios": "apple", "windows": "windows-version", "msi": "windows-version", "postgres": "db-majorminor",
	"postgresql": "db-majorminor", "mysql": "db-majorminor", "mariadb": "db-majorminor",
}

// genericScheme judges ecosystems this package has no rules for: dotted numbers
// with pre-release words, ordered the way the matcher's fallback orders them.
const genericScheme = "generic"

// NormalizeEcosystem lowercases an ecosystem name and drops a release suffix as
// OSV writes it (Debian:12, Alpine:v3.19, Ubuntu:22.04:LTS).
func NormalizeEcosystem(ecosystem string) string {
	e := strings.ToLower(strings.TrimSpace(ecosystem))
	if i := strings.IndexByte(e, ':'); i >= 0 {
		e = e[:i]
	}
	return e
}

// SchemeFor returns the scheme id that handles an ecosystem's package versions,
// or "generic" when the ecosystem is unknown.
func SchemeFor(ecosystem string) string {
	if id, ok := ecosystemScheme[NormalizeEcosystem(ecosystem)]; ok {
		if _, registered := registry[id]; registered {
			return id
		}
	}
	return genericScheme
}

// Classify judges one version string under the scheme of its ecosystem.
func Classify(ecosystem, v string) Info {
	return ClassifyScheme(SchemeFor(ecosystem), v)
}

// Order compares two versions under the scheme of their ecosystem. ok is false
// when either is not a version of that scheme.
func Order(ecosystem, a, b string) (int, bool) {
	return CompareScheme(SchemeFor(ecosystem), a, b)
}

// genericAlgo orders unknown ecosystems as dotted numbers and treats the usual
// pre-release words as unstable. It is deliberately the weakest engine here.
type genericAlgo struct{}

func (genericAlgo) compare(a, b string) (int, bool) {
	a, b = strings.TrimPrefix(strings.TrimSpace(a), "v"), strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == "" || b == "" || !isDigit(a[0]) || !isDigit(b[0]) {
		return 0, false
	}
	return compareGeneric(a, b)
}

func (genericAlgo) classify(v string) (bool, bool, []string) {
	v = strings.TrimSpace(v)
	if t := strings.TrimPrefix(v, "v"); t == "" || !isDigit(t[0]) {
		return unparseable()
	}
	reasons := distroUnstable(v, "", distroRules{})
	if strings.Contains(v, "-") && len(reasons) == 0 {
		// A hyphen suffix on dotted numbers is a pre-release unless it is a
		// plain revision number (1.2.3-4).
		if _, tail, _ := strings.Cut(v, "-"); !digitsRe.MatchString(tail) {
			reasons = append(reasons, ReasonPrerelease)
		}
	}
	return verdict(dedupe(reasons)...)
}

func init() { registry[genericScheme] = genericAlgo{} }
