# Version schemes

Generated from `version/schemes.json` by `go run ./version/cmd/gen-schemes-doc`. Do not edit by hand.

Every package ecosystem orders versions in its own way, and each marks "not a release" differently.
Safe Harbour needs both: the order, to find the highest release, and the stability rule, to skip
pre-releases, snapshots and nightly builds. This page records each scheme's rules, the sources they
come from, and where an engine knowingly differs from its reference implementation.

## The four outcomes

| Outcome | Definition |
| --- | --- |
| `latest` | The highest stable release (pre-releases skipped). For a package whose versions cannot be ordered by number, the most recent stable release by date. |
| `safest` | The highest stable release with no known vulnerability, exploit or malware report. |
| `stable` | The stable release closest to the version you run, so the upgrade is as small as possible. |
| `rolling` | Every version published on the most recent release day (UTC), pre-releases included. As a fix strategy, the member closest to the version you run. |

Every outcome is drawn from the clean versions only. `rolling` is a list; where a single string is
needed it is joined with a comma, which no concrete version contains (`version.EncodeRolling`).

## How a package is judged

1. The ecosystem name selects a scheme (`version.SchemeFor`); an unknown ecosystem uses the `generic` scheme.
2. Each version is classified: is it a version of the scheme at all, and is it stable? The reasons an
   unstable version is skipped are `prerelease`, `dev`, `snapshot`, `nightly`, `milestone`, `build-metadata`,
   `local-version`, `pseudo-version`, `git-snapshot`, `branch-ref`, `floating-tag` and `digest`.
3. The package is **orderable** when at least 80% of its real versions parse under the scheme, the scheme
   can order versions from the string, and the package has not switched between calendar-year and ordinary
   majors. An orderable package takes its highest stable release as `latest`; any other takes the most
   recent one by release date.

A release date decides only what the version string cannot. A point release on an old branch is newer by
date than the true latest and must never win on that account.

## Schemes

67 schemes. Ordering is `exact` where the engine reproduces the reference implementation on every
recorded vector, `approximate` where it knowingly differs (see known gaps), and `none` where the string
alone cannot be ordered.

| Scheme | Ecosystems | Ordering | Fidelity | Recency only |
| --- | --- | --- | --- | --- |
| [Bioconductor (R x.y.z with parity)](#bioconductor-r-xyz-with-parity) | `bioconductor` | `cran` | exact | false |
| [Cargo / crates.io (Rust semver crate)](#cargo--cratesio-rust-semver-crate) | `cargo`, `crates.io` | `semver-cargo` | exact | false |
| [Clojars / Leiningen / tools.deps (Maven order)](#clojars--leiningen--toolsdeps-maven-order) | `clojars`, `clojure` | `maven` | approximate | false |
| [CocoaPods (Pod::Version)](#cocoapods-podversion) | `cocoapods` | `rubygems` | approximate | false |
| [Composer / Packagist](#composer--packagist) | `composer`, `packagist` | `composer` | exact | false |
| [Conan 2 (ConanCenter)](#conan-2-conancenter) | `conan`, `conancenter` | `conan` | exact | false |
| [CPAN (decimal and dotted version.pm)](#cpan-decimal-and-dotted-versionpm) | `cpan` | `cpan` | exact | false |
| [CRAN (R package_version)](#cran-r-packageversion) | `cran` | `cran` | exact | false |
| [Go modules (MVS, pseudo-versions)](#go-modules-mvs-pseudo-versions) | `golang`, `go`, `gomod` | `semver-go` | exact | false |
| [Hackage (PVP / Cabal Version)](#hackage-pvp--cabal-version) | `hackage`, `ghc` | `hackage` | exact | false |
| [Helm charts (Chart.yaml version)](#helm-charts-chartyaml-version) | `helm` | `semver-loose` | exact | false |
| [Hex (Elixir Version)](#hex-elixir-version) | `hex` | `semver-hex` | exact | false |
| [Julia VersionNumber / Pkg registry](#julia-versionnumber--pkg-registry) | `julia` | `julia` | exact | false |
| [LuaRocks rockspec versions](#luarocks-rockspec-versions) | `luarocks` | `luarocks` | exact | false |
| [NuGet (SemVer 2 + 4-part legacy)](#nuget-semver-2--4-part-legacy) | `nuget` | `semver-nuget` | exact | false |
| [opam (Debian-style)](#opam-debian-style) | `opam` | `opam` | exact | false |
| [pub (Dart / Flutter)](#pub-dart--flutter) | `pub` | `semver-pub` | exact | false |
| [rebar3 (vendored ec_semver, Hex packages)](#rebar3-vendored-ecsemver-hex-packages) | `rebar3`, `erlang` | `rebar3` | exact | false |
| [SemVer 2.0.0 / npm node-semver](#semver-200--npm-node-semver) | `npm`, `yarn`, `pnpm` | `semver` | exact | false |
| [SwiftPM (git tags / registry)](#swiftpm-git-tags--registry) | `swift`, `swifturl` | `semver-loose` | exact | false |
| [Terraform Registry (go-version)](#terraform-registry-go-version) | `terraform` | `semver-loose` | approximate | false |
| [vcpkg (version, version-semver, version-date, version-string)](#vcpkg-version-version-semver-version-date-version-string) | `vcpkg` | `vcpkg` | exact | partial |
| [ZeroVer and unversioned refs](#zerover-and-unversioned-refs) | `zerover` | `semver` | exact | false |
| [conda VersionOrder](#conda-versionorder) | `conda`, `conda-forge`, `anaconda`, `mamba`, `pixi` | `conda` | exact | false |
| [Coursier / sbt version ordering](#coursier--sbt-version-ordering) | `sbt`, `coursier`, `mill`, `scala-cli`, `bloop` | `custom:coursier` | exact | false |
| [Gradle version ordering](#gradle-version-ordering) | `gradle`, `ivy`, `ant` | `gradle` | exact | false |
| [Apache Ivy latest-revision](#apache-ivy-latest-revision) | `ivy`, `ant` | `custom:ivy` | exact | false |
| [Maven ComparableVersion](#maven-comparableversion) | `maven`, `java`, `jvm`, `kotlin`, `scala`, `clojars`, and 10 more | `maven` | approximate | false |
| [PEP 440 (PyPI, pip)](#pep-440-pypi-pip) | `pypi`, `pip`, `python`, `pep440`, `uv`, `poetry` | `pep440` | exact | false |
| [RubyGems Gem::Version](#rubygems-gemversion) | `rubygems`, `gem`, `ruby`, `bundler` | `rubygems` | exact | false |
| [Alpine apk (digits, letter, suffixes, ~hash, -rN)](#alpine-apk-digits-letter-suffixes-hash--rn) | `alpine`, `alpaquita`, `bellsoft hardened containers`, `minimos` | `alpine` | exact | false |
| [Android OSV version (<branch>[L][-qprN][-next]:<SPL>)](#android-osv-version-branchl-qprn-nextspl) | `android` | `custom:android-osv` | approximate | partial |
| [Arch pacman/libalpm (epoch:pkgver-pkgrel)](#arch-pacmanlibalpm-epochpkgver-pkgrel) | `arch`, `archlinux`, `cachyos`, `manjaro`, `endeavouros`, `aur` | `arch` | exact | false |
| [Bitnami X.Y.Z[-revision] (revision-aware SemVer)](#bitnami-xyz-revision-revision-aware-semver) | `bitnami` | `bitnami` | exact | false |
| [Debian dpkg (epoch:upstream-revision)](#debian-dpkg-epochupstream-revision) | `debian`, `ubuntu`, `kali`, `raspbian`, `raspberry pi os`, `linuxmint`, and 5 more | `debian` | exact | false |
| [Gentoo ebuild version (PMS)](#gentoo-ebuild-version-pms) | `gentoo`, `portage` | `gentoo` | exact | false |
| [Homebrew formula version (Version/PkgVersion)](#homebrew-formula-version-versionpkgversion) | `homebrew`, `brew` | `homebrew` | exact | false |
| [Linux kernel mainline (x.y[.z[.w]][-rcN])](#linux-kernel-mainline-xyzw-rcn) | `linux` | `custom:linux-kernel` | approximate | false |
| [Nix/nixpkgs (pname-version, compareVersions)](#nixnixpkgs-pname-version-compareversions) | `nix`, `nixpkgs`, `nixos` | `nix` | exact | false |
| [RPM (epoch:version-release)](#rpm-epochversion-release) | `red hat`, `rhel`, `redhat`, `centos`, `fedora`, `rocky linux`, and 16 more | `rpm` | exact | false |
| [Wolfi/Chainguard apk (go-apk strict subset, melange -rN)](#wolfichainguard-apk-go-apk-strict-subset-melange--rn) | `wolfi`, `chainguard`, `docker hardened images`, `cleanstart` | `wolfi` | approximate | false |
| [Apple OS versions and build numbers (macOS, iOS, bundles)](#apple-os-versions-and-build-numbers-macos-ios-bundles) | `apple`, `cocoapods-bundle`, `ios`, `ipados`, `macos`, `swift` | `dotted-int` | approximate | partial |
| [Where "highest number wins" or "newest date wins" gives the WRONG latest (LTS lines, back-port point releases, floating majors, 0.x carets)](#where-highest-number-wins-or-newest-date-wins-gives-the-wrong-latest-lts-lines-back-port-point-releases-floating-majors-0x-carets) | `all`, `docker`, `github`, `github-actions`, `java`, `linux`, and 5 more | `none` | none | partial |
| [Browser extension manifest versions (Chrome, Edge, Firefox)](#browser-extension-manifest-versions-chrome-edge-firefox) | `browser-extension`, `chrome`, `chrome-extension`, `edge`, `firefox`, `webstore` | `dotted-int` | exact | false |
| [CalVer and date-based versions (calver.org)](#calver-and-date-based-versions-calverorg) | `calver`, `android`, `docker`, `generic`, `github`, `homeassistant`, and 5 more | `calver` | exact | false |
| [Chocolatey packages (NuGet versions)](#chocolatey-packages-nuget-versions) | `choco`, `chocolatey`, `nuget-choco` | `semver-nuget` | exact | false |
| [Database majors: PostgreSQL, MySQL, MariaDB](#database-majors-postgresql-mysql-mariadb) | `generic`, `mariadb`, `mysql`, `postgres`, `postgresql` | `dotted-int` | approximate | false |
| [Docker / OCI image tags](#docker--oci-image-tags) | `docker`, `ecr`, `ghcr`, `oci`, `quay` | `dotted-int` | approximate | partial |
| [Git refs (branches, commit SHAs, git-describe strings)](#git-refs-branches-commit-shas-git-describe-strings) | `git`, `github-ref`, `gitlab-ref`, `gitref`, `oss-fuzz` | `none` | none | true |
| [GitHub tags, Releases and GitHub Actions refs](#github-tags-releases-and-github-actions-refs) | `github`, `github-actions`, `github-release` | `semver` | approximate | partial |
| [Go toolchain versions (go1.27.3, go1.27rc3) and module pseudo-versions](#go-toolchain-versions-go1273-go127rc3-and-module-pseudo-versions) | `go`, `go-toolchain`, `golang`, `gomod` | `custom:go-toolchain` | exact | false |
| [Java / OpenJDK version strings (JEP 223), EA builds, legacy 1.8.0_xxx](#java--openjdk-version-strings-jep-223-ea-builds-legacy-180xxx) | `java`, `jdk`, `maven-jdk`, `openjdk`, `temurin` | `custom:jep223` | exact | false |
| [JetBrains Marketplace plugins and IDE build numbers](#jetbrains-marketplace-plugins-and-ide-build-numbers) | `intellij`, `jetbrains`, `jetbrains-plugin` | `semver` | exact | partial |
| [Letter-suffix and encoded schemes: zlib, libpng, curl, bash, sqlite](#letter-suffix-and-encoded-schemes-zlib-libpng-curl-bash-sqlite) | `bash`, `curl`, `generic`, `github`, `libpng`, `sqlite`, and 1 more | `letter-suffix` | approximate | false |
| [Linux kernel (mainline, stable, longterm, -rc, linux-next)](#linux-kernel-mainline-stable-longterm--rc-linux-next) | `kernel`, `linux`, `linux-kernel` | `semver-loose` | exact | false |
| [Node.js runtime (even/odd lines, LTS codenames, nightly/rc/v8-canary/test dists)](#nodejs-runtime-evenodd-lines-lts-codenames-nightlyrcv8-canarytest-dists) | `node`, `nodejs`, `runtime-node` | `semver` | exact | false |
| [npm dist-tags as a channel signal (SemVer versions with unstable channels)](#npm-dist-tags-as-a-channel-signal-semver-versions-with-unstable-channels) | `npm`, `pnpm`, `yarn` | `semver` | exact | false |
| [OpenSSL (letter-suffix patch releases <= 1.1.1; SemVer-style from 3.0)](#openssl-letter-suffix-patch-releases--111-semver-style-from-30) | `generic`, `github`, `openssl` | `letter-suffix` | exact | false |
| [PHP (and the version_compare special-form ordering)](#php-and-the-versioncompare-special-form-ordering) | `composer`, `packagist`, `php` | `custom:php-version-compare` | exact | false |
| [CPython interpreter releases (not PyPI packages)](#cpython-interpreter-releases-not-pypi-packages) | `cpython`, `pyenv`, `python`, `python-runtime` | `pep440` | exact | false |
| [Rust toolchain channels (stable / beta / nightly / dated nightly)](#rust-toolchain-channels-stable--beta--nightly--dated-nightly) | `rust`, `rust-toolchain`, `rustc`, `rustup` | `semver` | approximate | partial |
| [Scoop manifests](#scoop-manifests) | `scoop` | `custom:scoop-compare-version` | approximate | partial |
| [Ubuntu releases (YY.MM CalVer with .N point releases and LTS)](#ubuntu-releases-yymm-calver-with-n-point-releases-and-lts) | `docker-ubuntu`, `ubuntu`, `ubuntu-release` | `calver` | exact | false |
| [Unity editor versions (2022.3.10f1, 6000.0.23f1)](#unity-editor-versions-2022310f1-6000023f1) | `unity`, `unity3d`, `upm-editor` | `custom:unity-stream` | approximate | false |
| [VS Code Marketplace and Open VSX extensions](#vs-code-marketplace-and-open-vsx-extensions) | `openvsx`, `vsce`, `vscode`, `vscode-marketplace` | `semver` | exact | false |
| [Windows file versions (a.b.c.d), MSI ProductVersion, OS build numbers, KB ids](#windows-file-versions-abcd-msi-productversion-os-build-numbers-kb-ids) | `kb`, `msi`, `nuget-windows`, `windows`, `windows-update` | `dotted-int` | approximate | partial |
| [Windows Package Manager (winget) PackageVersion](#windows-package-manager-winget-packageversion) | `windows-package-manager`, `winget`, `winget-pkgs` | `custom:winget-parts` | approximate | partial |

## SemVer-shaped registries

### Bioconductor (R x.y.z with parity)

`bioconductor`. Ecosystems: `bioconductor`. purl types: `bioconductor?`.

Sources: <https://contributions.bioconductor.org/versionnum.html> <https://bioconductor.org/about/removed-packages/>

**Stable release rule.** Stable iff the version parses and y (second component) is even.

**Pre-release.** No syntax; odd middle number y means devel branch, even y means release branch (0.99.z for new packages).

**Build metadata.** No build metadata.

**Yanked or deprecated.** Packages are deprecated in release N and removed in N+1 (removed-packages page); no per-version flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| odd-minor-unstable | `x.y.z with y odd` | `1.3.4`, `0.99.0`, `1.99.5` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | odd y (devel) |

**Conventions with no SemVer equivalent**

- x.99.z is bumped to (x+1).0.z at release.
- Versions are scoped per Bioconductor release (3.20, 3.21...).

**Known gaps**

- Annotation/experiment packages may use other patterns.
- Release numbering of Bioconductor itself not covered by the rules page.

### Cargo / crates.io (Rust semver crate)

`cargo`. Ecosystems: `cargo`, `crates.io`. purl types: `cargo`.

Sources: <https://doc.rust-lang.org/cargo/reference/manifest.html#the-version-field> <https://doc.rust-lang.org/cargo/reference/registry-index.html> <https://github.com/dtolnay/semver>

**Stable release rule.** Stable iff no pre-release part and not yanked. 0.y.z is stable.

**Pre-release.** SemVer -<ident>(.<ident>)*; lower than the release; requirements exclude pre-releases unless the requirement itself names one on the same X.Y.Z.

**Build metadata.** +meta accepted; the semver crate Ord DOES compare it as a final tiebreak (1.0.0 < 1.0.0+9 < 1.0.0+a); Cargo ignores it for matching; the index forbids two versions differing only by build. Not a stability signal.

**Yanked or deprecated.** Registry index field yanked:true per version (cargo yank / --undo); yanked versions are skipped for new resolution but lockfiles and downloads still work. No per-version deprecation flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-alpha`, `1.0.0-rc.1`, `1.0.0-beta+exp` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | same syntax; compared by the crate, ignored by Cargo matching; -sys crates use it for bundled C library version |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- 0.y.z compatibility boundary is the left-most non-zero component.
- Caret is the default operator; bare * is rejected by crates.io.
- rust_version (MSRV) field in the index.

**Known gaps**

- crates.io publish-time rejection text for build metadata was not located.
- Build-metadata ordering in the crate differs from semver.org.

### Clojars / Leiningen / tools.deps (Maven order)

`clojars`. Ecosystems: `clojars`, `clojure`. purl types: `maven`.

Sources: <https://maven.apache.org/pom.html#version-order-specification> <https://github.com/clojars/clojars-web/wiki/About> <https://maven.apache.org/resolver/>

**Stable release rule.** Stable iff no qualifier among alpha/beta/milestone/rc/cr/snapshot/dev/nightly/pre/preview and no timestamped snapshot form. Unknown qualifiers cannot be detected by ordering and need name matching.

**Pre-release.** Qualifier after -: alpha < beta < milestone < rc=cr < snapshot < release(=final=ga) < sp; unknown qualifiers (dev, nightly, foo) sort ABOVE the release.

**Build metadata.** No build-metadata concept; +x is an unknown qualifier that sorts above the release.

**Post-release.** -sp<N> and numeric sub-lists (1.0-1) are post-releases.

**Yanked or deprecated.** None: Clojars releases are immutable and deletion is discouraged and by caretaker request. No flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| snapshot | `-SNAPSHOT (case-insensitive) or -YYYYMMDD.HHMMSS-N` | `1.0-SNAPSHOT`, `1.0-20240101.123456-1` |
| prerelease | `-<ident>(.<ident>)*` | `1.0-alpha-1`, `1.0-RC1`, `1.0-m1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | sp / numeric sub-list |
| prerelease | qualifier after - |

**Conventions with no SemVer equivalent**

- Tokenizer splits on . - _ and digit/letter transitions; trailing 0/final/ga/release trimmed.
- Hyphen starts a sub-list, dot continues the list.
- SNAPSHOT deploys are mutable; releases immutable.

**Known gaps**

- Maven ComparableVersion and Maven Resolver GenericVersion disagree (1.0-1 vs 1.0.1); vectors use the Resolver.
- Clojars SNAPSHOT page not fetched.

### CocoaPods (Pod::Version)

`cocoapods`. Ecosystems: `cocoapods`. purl types: `cocoapods`.

Sources: <https://github.com/CocoaPods/Core/blob/master/lib/cocoapods-core/version.rb> <https://guides.cocoapods.org/syntax/podspec.html>

**Stable release rule.** Stable iff, after removing +meta, the string has no letter and no hyphen. Note 1.1.1a and 1.0.0-1 count as pre-release.

**Pre-release.** RubyGems segments: a letter segment (1.0.0.beta2, 1.0.0a) or semver-style -id (1.0.0-rc.1) sorts below the release; prerelease? is true for any letter or hyphen.

**Build metadata.** +meta accepted and stripped before segment compare, but <=> falls back to a full-string tiebreak; not a stability signal.

**Post-release.** An extra numeric segment (1.0.0.1) is above 1.0.0.

**Yanked or deprecated.** Podspec spec.deprecated = true and spec.deprecated_in_favor_of (package-level). Trunk specs cannot be deleted.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `any [a-zA-Z-] in the version minus +meta` | `1.0.0-beta.1`, `1.0.0.rc1`, `1.0.0a` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +meta, stripped for order |
| epoch | none |
| postRelease | extra numeric segment |
| prerelease | letter segment or -id |

**Conventions with no SemVer equivalent**

- Any number of segments; ~> 1.0 means >=1.0 <2.0.
- Podfile can depend on :git/:tag/:branch/:commit instead of versions.

**Known gaps**

- 1.0.0-1 is prerelease? but sorts above 1.0.0.
- == ignores +meta while <=> breaks ties by string; rubygems id is approximate for Pod::Version hyphen forms.

### Composer / Packagist

`composer`. Ecosystems: `composer`, `packagist`. purl types: `composer`.

Sources: <https://getcomposer.org/doc/articles/versions.md> <https://getcomposer.org/doc/04-schema.md> <https://github.com/composer/semver>

**Stable release rule.** Stable iff parseStability(normalized) is 'stable' (no dev/alpha/beta/RC word, not a dev-* or N.x-dev branch). patch/p/pl suffixes are stable. Always normalize before comparing.

**Pre-release.** Words after the numeric core: -dev < -alpha[N] (a) < -beta[N] (b) < -RC[N] < release; spellings normalized (rc.1 -> RC1).

**Build metadata.** +build is stripped by normalize; not a stability signal.

**Post-release.** -patch[N] / -p[N] / -pl[N] sorts ABOVE the release and is stable.

**Yanked or deprecated.** Package-level abandoned (true or replacement name) in composer.json/Packagist. No per-version yank flag found.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-(alpha\|a\|beta\|b\|RC)[.]?N` | `1.0.0-beta2`, `1.0.0-RC1` |
| dev | `-dev suffix` | `1.0.0-dev` |
| branch-ref | `dev-<branch> or N.x-dev` | `dev-main`, `1.x-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | stripped |
| epoch | none |
| postRelease | patch/p/pl suffix (no SemVer equivalent) |
| prerelease | alpha/beta/RC/dev words |

**Conventions with no SemVer equivalent**

- Branch versions dev-<name> and numeric branches N.x-dev; extra.branch-alias maps a branch to a version.
- minimum-stability (default stable) and prefer-stable filter by stability; per-requirement @dev flags.
- Up to 4 numeric parts; v prefix removed.

**Known gaps**

- Comparator in composer/semver does not normalize (1.0.0 < 1.0.0.0).
- parseStability('master') says stable; treat bare master as a branch.

### Conan 2 (ConanCenter)

`conan`. Ecosystems: `conan`, `conancenter`. purl types: `conan`.

Sources: <https://docs.conan.io/2/tutorial/versioning/version_ranges.html> <https://docs.conan.io/2/reference/conanfile/attributes.html> <https://github.com/conan-io/conan/blob/develop2/conan/internal/model/version.py>

**Stable release rule.** Stable iff the part after the first - (before +) is empty. Letter patches like 1.1.1w and PEP 440 forms like 1.0.0.dev1 are NOT pre-releases to Conan.

**Pre-release.** Text after the first - (before +): lower than the same core; ranges exclude pre-releases unless include_prerelease or resolve_prereleases=True.

**Build metadata.** +build after the last +; compared among non-pre-releases; not a stability signal.

**Yanked or deprecated.** Recipe attribute deprecated (warning); packages removed with conan remove. No yank flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-alpha`, `1.0.0-rc.1`, `1.2.3-nightly.20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | after last +, compared |
| epoch | none |
| postRelease | extra segments / letters |
| prerelease | after first - |

**Conventions with no SemVer equivalent**

- Any number of segments and lowercase letters; trailing zeros ignored.
- Recipe and package revisions (RREV/PREV) order builds of one version.
- ConanCenter uses cci.YYYYMMDD for unreleased upstreams.

**Known gaps**

- Mixed digit/letter patches give a non-transitive order (1.1.1a vs 1.1.9 vs 1.1.10).
- Version() accepts any string; 'no digits' is treated as unparseable downstream.

### CPAN (decimal and dotted version.pm)

`cpan`. Ecosystems: `cpan`. purl types: `cpan`.

Sources: <https://perldoc.perl.org/version> <https://metacpan.org/pod/CPAN::Meta::Spec#Version-Formats> <https://pause.perl.org/pause/query?ACTION=pause_operating_model>

**Stable release rule.** Stable iff the version has no underscore (is_alpha false) and the distribution is not -TRIAL / release_status stable.

**Pre-release.** Underscore in the version (1.02_03, v1.2.3_4) marks an alpha/developer release; version.pm 0.9934 ignores it for comparison; PAUSE does not index developer releases (also -TRIAL dist suffix).

**Build metadata.** No build metadata.

**Yanked or deprecated.** No per-version flag found; deletion moves a release to BackPAN. MetaCPAN deprecation key not verified.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| dev | `underscore inside the version, or -TRIAL[N] in the distribution name` | `1.02_03`, `v1.2.3_4` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | underscore / TRIAL |

**Conventions with no SemVer equivalent**

- Decimal 1.02 is v1.20.0 (groups of three digits), dotted needs a v or two dots; so 1.10 < 1.2 < 1.9.
- Moving from decimal to dotted can go backwards (1.23 = v1.230.0).

**Known gaps**

- Older docs say alpha sorts below the plain version; installed 0.9934 does not.
- Deprecation mechanics unverified.

### CRAN (R package_version)

`cran`. Ecosystems: `cran`. purl types: `cran`.

Sources: <https://cran.r-project.org/doc/manuals/r-release/R-exts.html#The-DESCRIPTION-file> <https://github.com/wch/r-source/blob/trunk/src/main/util.c> <https://r-pkgs.org/lifecycle.html>

**Stable release rule.** Stable iff the version parses and the 4th component is below 9000 (convention).

**Pre-release.** None in the format; development versions use a 4th component starting at 9000 by convention (1.2.3.9000, sorts above 1.2.3).

**Build metadata.** No build metadata.

**Yanked or deprecated.** Packages are archived wholesale (moved to Archive/, all versions still downloadable); no per-version flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| dev | `x.y.z.9000 (4th component >= 9000)` | `1.2.3.9000`, `0.0.0.9000` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | none (.9000 convention) |

**Conventions with no SemVer equivalent**

- '.' and '-' are equivalent separators (1.2-3 == 1.2.3); trailing zeros ignored.
- At least two components for package_version; components are integers (0.9 < 0.75).

**Known gaps**

- R not installed; ordering from a port of util.c.
- CRAN does not enforce the .9000 convention.

### Go modules (MVS, pseudo-versions)

`go`. Ecosystems: `golang`, `go`, `gomod`. purl types: `golang`.

Sources: <https://go.dev/ref/mod#versions> <https://go.dev/ref/mod#pseudo-versions> <https://pkg.go.dev/golang.org/x/mod/semver>

**Stable release rule.** Stable iff valid vX.Y.Z[+meta] with no pre-release part (pseudo-versions are pre-releases) and not retracted. v0.x is stable here even though go.dev calls it 'unstable' compatibility-wise. @latest prefers highest release, then pre-release, then pseudo-version.

**Pre-release.** vX.Y.Z-<pre>; lower than the release. Pseudo-versions (vX.0.0-yyyymmddhhmmss-sha, vX.Y.Z-pre.0.ts-sha, vX.Y.(Z+1)-0.ts-sha) are pre-releases that sort above their base and below the next tag.

**Build metadata.** +meta ignored in compare; +incompatible marks a v2+ tag without go.mod and is a normal release; not a stability signal.

**Epoch.** Major version path suffix /vN plays the epoch role.

**Yanked or deprecated.** go.mod retract directive (read from the module's latest version) hides versions from list/latest; '// Deprecated:' comment before module deprecates the whole module. Not in the version string.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `v1.0.0-rc.1` |
| pseudo-version | `v<X>.<Y>.<Z>-(pre.)?0.<14 digits>-<sha> or v<X>.0.0-<14 digits>-<sha>` | `v0.0.0-20191109021931-daa7c04131f5`, `v1.2.4-0.20191109021931-daa7c04131f5` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | ignored; reused for +incompatible |
| epoch | path suffix /vN |
| postRelease | none |
| prerelease | identical; pseudo-version is a pre-release encoding a commit |

**Conventions with no SemVer equivalent**

- Mandatory lowercase v prefix; x/mod/semver also accepts v1 and v1.2 shorthands.
- Module path must end /vN for N>=2.
- Minimal version selection: highest of required minimums, never newest.

**Known gaps**

- IsPseudoVersion regex reconstructed from behaviour plus docs.
- v1.2.3-20191109021931-sha is NOT a pseudo-version despite the lookalike.

### Hackage (PVP / Cabal Version)

`hackage`. Ecosystems: `hackage`, `ghc`. purl types: `hackage`.

Sources: <https://pvp.haskell.org/> <https://cabal.readthedocs.io/en/stable/cabal-package-description-file.html> <https://hackage.haskell.org/api>

**Stable release rule.** Every parseable N(.N)* version is a normal release; exclude versions the registry lists as deprecated or unpreferred.

**Pre-release.** None; version tags are unsupported. Pre-release-like states are package candidates, not version strings.

**Build metadata.** No build metadata.

**Post-release.** None; extra components are patch-like.

**Yanked or deprecated.** Registry: preferred-versions (normal / unpreferred / deprecated) and package-level deprecated flag via /package/:p/preferred and /deprecated.

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | none |

**Conventions with no SemVer equivalent**

- Component list ordering: 1 < 1.0 < 1.0.0 (no zero padding).
- Major version is the first TWO components A.B.
- ^>= operator and mandatory upper bounds.

**Known gaps**

- Leading zeros in components unverified.
- Exact JSON shape of deprecated/unpreferred lists not fetched.

### Helm charts (Chart.yaml version)

`helm`. Ecosystems: `helm`. purl types: `helm?`.

Sources: <https://helm.sh/docs/topics/charts/#charts-and-versioning> <https://github.com/Masterminds/semver> <https://helm.sh/docs/helm/helm_search_repo/>

**Stable release rule.** Stable iff the lenient semver.NewVersion parse has no pre-release part. appVersion is free text and irrelevant.

**Pre-release.** SemVer -<pre>; lower than the release; hidden unless --devel (equivalent to >0.0.0-0) or the constraint names a pre-release.

**Build metadata.** +meta allowed (1.2.3-alpha.1+ef365), ignored in compare; replaced by _ in OCI tags; not a stability signal.

**Yanked or deprecated.** Chart.yaml deprecated: true (and the same flag in the repo index.yaml entry). No yank.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc.1`, `1.0.0-alpha.1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | identical, ignored |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- Lenient parse accepts v prefix, 1.0 and 1 and leading zeros.
- Two version axes: chart version and appVersion.
- OCI tags replace + with _.

**Known gaps**

- Docs say not enforced strictly and not updated for Helm 4.

### Hex (Elixir Version)

`hex`. Ecosystems: `hex`. purl types: `hex`.

Sources: <https://elixir.hexdocs.pm/Version.html> <https://hex.pm/docs/publish> <https://hex.hexdocs.pm/Mix.Tasks.Hex.Retire.html>

**Stable release rule.** Stable iff no pre-release part. Hex runs requirements with allow_pre false, so pre-releases only match when the requirement names one.

**Pre-release.** Strict SemVer -<pre>; lower than the release; integer ids < string ids.

**Build metadata.** +build accepted and ignored in compare (compare returns :eq); not a stability signal.

**Yanked or deprecated.** mix hex.retire PACKAGE VERSION REASON (renamed, deprecated, security, invalid, other) sets retirement metadata on the release; still resolvable. mix hex.publish --revert within one hour removes.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc.1`, `1.0.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | identical, ignored |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- ~> pessimistic operator (~> 2.0 = >=2.0.0 and <3.0.0).
- All three numeric parts are required.
- Retirement reasons are informational; resolution is not blocked.

**Known gaps**

- Whether hex.pm accepts build metadata at publish time was not verified.

### Julia VersionNumber / Pkg registry

`julia`. Ecosystems: `julia`. purl types: `julia?`.

Sources: <https://docs.julialang.org/en/v1/manual/strings/#man-version-number-literals> <https://github.com/JuliaLang/julia/blob/master/base/version.jl> <https://pkgdocs.julialang.org/v1/compatibility/>

**Stable release rule.** Stable iff the parsed prerelease tuple is empty and the version is not yanked. Pkg compat itself ignores pre-release and build.

**Pre-release.** -<ident>(.<ident>)* (hyphen optional if the first id starts with a letter); lower than the release; a bare trailing - is the lowest pre-release.

**Build metadata.** +build exists and IS compared (1.0.0 < 1.0.0+1 < 1.0.0+a); trailing + is a supremum sentinel; not a stability signal.

**Yanked or deprecated.** Registry Versions.toml yanked = true per version. No deprecation flag found.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.12.0-beta2`, `1.11.0-rc1` |
| dev | `-DEV[.N]` | `1.12.0-DEV`, `1.12.0-DEV.1234` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +id, compared |
| epoch | none |
| postRelease | none |
| prerelease | same (hyphen optional) |

**Conventions with no SemVer equivalent**

- Everything except the major is optional; v prefix optional and case-insensitive.
- Compat: caret default, ^0.2.3 = [0.2.3,0.3.0).
- Pkg compat bounds use major.minor.patch only.

**Known gaps**

- Ported from Julia source, not executed.
- Registrator policy on pre-release publication not located.

### LuaRocks rockspec versions

`luarocks`. Ecosystems: `luarocks`. purl types: `luarocks`.

Sources: <https://github.com/luarocks/luarocks/blob/main/src/luarocks/core/vers.lua> <https://github.com/luarocks/luarocks/tree/main/docs>

**Stable release rule.** Stable iff no alpha/beta/pre/rc word and not dev/scm/cvs. Revisions (-2) do not make it unstable.

**Pre-release.** Words alpha/beta/pre/rc get negative weights so they sort below the release; dev/scm/cvs get huge positive weights and sort above every release.

**Build metadata.** No build metadata; a + breaks the tokenizer.

**Post-release.** Rockspec revision -N (packaging) compared last.

**Yanked or deprecated.** None found in the rockspec; luarocks.org management not examined.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `alpha\|beta\|pre\|rc word` | `1.0-rc1-1`, `1.0beta-1` |
| dev | `dev\|scm\|cvs (VCS head)` | `scm-1`, `dev-1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | revision -N |
| prerelease | word token |

**Conventions with no SemVer equivalent**

- version-revision form; revision bumps for rockspec fixes.
- scm/dev rocks build from source control.
- == compares component count so 1.0 ~= 1.0.0 while < treats them equal.

**Known gaps**

- Leading v is not stripped (v1.0 sorts as 0.118.0).
- Rockspec format doc not fetched.
- Order is not consistent across lengths.

### NuGet (SemVer 2 + 4-part legacy)

`nuget`. Ecosystems: `nuget`. purl types: `nuget`.

Sources: <https://learn.microsoft.com/en-us/nuget/concepts/package-versioning> <https://www.nuget.org/packages/NuGet.Versioning>

**Stable release rule.** Stable iff there is no hyphen label. Revision (4th part) and metadata do not make it unstable. Resolution picks stable only unless the range names a pre-release.

**Pre-release.** Hyphen label after Major[.Minor[.Patch[.Revision]]]; any label is lower than the release; labels compared case-insensitively, numeric < alphanumeric.

**Build metadata.** +meta accepted (SemVer2), ignored in compare, normalized away; not a stability signal.

**Post-release.** 4th Revision numeric segment acts like a legacy post-release component (1.0.0.1 > 1.0.0).

**Yanked or deprecated.** nuget.org: unlist (listed=false; hidden from search, still restorable by exact version) and separate deprecation metadata (Legacy, Critical Bugs, Other + alternate package). Neither is in the version string.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-beta`, `1.0.0-preview.1.23456.7`, `1.0.0-ci-20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +meta, ignored |
| epoch | none |
| postRelease | 4th Revision segment |
| prerelease | hyphen label, case-insensitive |

**Conventions with no SemVer equivalent**

- Missing parts are zero: 1, 1.0, 1.0.0 and 1.0.0.0 are equal; leading zeros normalized (01.0.0 -> 1.0.0).
- Floating versions 1.* and 1.0.0-* ; lowest applicable version wins on restore.
- Interval ranges [1.0,2.0).

**Known gaps**

- Docs sentence about 'reverse alphabetical order' mis-describes the displayed descending list.
- SemVer1 label rules only matter for old clients.

### opam (Debian-style)

`opam`. Ecosystems: `opam`. purl types: `opam?`.

Sources: <https://opam.ocaml.org/doc/Manual.html> <https://github.com/ocaml/opam/blob/master/src/core/opamVersionCompare.ml>

**Stable release rule.** Stable iff there is no ~ in the version, it is not dev/master and has no +dev/+gitYYYY marker, and flags lack avoid-version/deprecated. Beware -rc and -beta forms sort above the release.

**Pre-release.** Convention only: ~suffix (1.0~beta) sorts before 1.0; opam has no pre-release syntax and -rc1 sorts ABOVE the release.

**Build metadata.** No build metadata; + suffix sorts after the base (variants such as 4.14.0+flambda) and is normally stable.

**Post-release.** +suffix or -N revision (last - splits a Debian-style revision).

**Yanked or deprecated.** opam file flags: avoid-version (lowest solver priority) and deprecated (same plus message). Flags live in the package's opam file.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `~<ident>` | `1.0~beta`, `5.0.0~alpha1` |
| dev | `dev \| master \| +dev \| ~dev \| +git<date>` | `dev`, `1.0+dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +suffix sorts after |
| epoch | none |
| postRelease | +suffix or -N |
| prerelease | ~suffix (convention) |

**Conventions with no SemVer equivalent**

- Alternating non-digit/digit run comparison; ~ < end < letters < other symbols.
- Package identity is name.version; version is everything after the first dot of the directory name.

**Known gaps**

- Ported from OCaml source, not executed.
- Pre-release classification is convention, not specified.

### pub (Dart / Flutter)

`pub`. Ecosystems: `pub`. purl types: `pub`.

Sources: <https://dart.dev/tools/pub/versioning> <https://github.com/dart-lang/pub_semver> <https://dart.dev/tools/pub/publishing>

**Stable release rule.** Stable iff no pre-release part and not retracted.

**Pre-release.** SemVer -<pre>; lower than the release; pub prefers stable and ^X.Y.Z upper bound is <(X+1).0.0-0 so next-major pre-releases are excluded.

**Build metadata.** +build accepted and ORDERED after the plain release (1.0.0 < 1.0.0+1); Dart uses +N as a non-API-changing bump. Not a stability signal.

**Post-release.** +N build suffix behaves like a post-release (pub ordering).

**Yanked or deprecated.** Per version retracted:true (pub.dev Admin, within 7 days; restorable). Package-level isDiscontinued (+replacedBy). Both are API/registry fields.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-dev.1`, `2.0.0-0`, `1.0.0-beta` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +N, compared (differs from semver.org) |
| epoch | none |
| postRelease | +N build number |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- 0.x shifted one slot: 0.1.2 -> 0.2.0 is breaking; ^0.1.2 = >=0.1.2 <0.2.0.
- SDK constraints use the same grammar.

**Known gaps**

- pub_semver accepts leading zeros (01.0.0, 1.0.0-01); pub.dev publish validation not tested.
- How pub.dev computes 'latest' is documented only informally.

### rebar3 (vendored ec_semver, Hex packages)

`rebar3`. Ecosystems: `rebar3`, `erlang`. purl types: `hex`.

Sources: <https://rebar3.org/docs/configuration/dependencies/> <https://github.com/erlang/rebar3/blob/main/vendor/erlware_commons/src/ec_semver.erl> <https://github.com/erlang/rebar3/blob/main/apps/rebar/src/rebar_semver.erl>

**Stable release rule.** Stable iff the parse succeeds and the pre-release list is empty. A bare Hex dependency ignores pre-releases; is_prerelease_or_build checks for - or + in the constraint.

**Pre-release.** -<id>(.<id>)*; lower than the release; the FIRST id is compared as text even when numeric (-10 < -2), later numeric ids as integers.

**Build metadata.** +build accepted and compared as a final tiebreak; not a stability signal.

**Post-release.** 4th numeric part (minpatch).

**Yanked or deprecated.** Hex retirement (see hex); rebar3 sources read do not interpret it. Git deps use tag/branch/ref pins in rebar.lock.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc1`, `1.0.0-alpha.1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +build, compared |
| epoch | none |
| postRelease | 4th numeric part |
| prerelease | identical, first id text-compared |

**Conventions with no SemVer equivalent**

- Optional v prefix, 1 to 4 numeric parts, missing parts are zero.
- Non-Hex deps: versions informational only.

**Known gaps**

- Executed parser accepted 1.0.0-x-y though the .peg looks stricter.
- May use verl for some Hex paths; not confirmed.

### SemVer 2.0.0 / npm node-semver

`semver`. Ecosystems: `npm`, `yarn`, `pnpm`. purl types: `npm`.

Sources: <https://semver.org/spec/v2.0.0.html> <https://github.com/npm/node-semver> <https://docs.npmjs.com/cli/v10/commands/npm-dist-tag>

**Stable release rule.** Stable iff the parsed version has no pre-release part (no hyphen before the first +). Build metadata and 0.y.z do not make it unstable. Strings that do not parse (latest, next, dist-tags) are not versions.

**Pre-release.** Suffix -<ident>(.<ident>)*; any pre-release is lower than the same X.Y.Z release; numeric ids < alphanumeric ids, ASCII order, more ids is higher.

**Build metadata.** +<ident>(.<ident>)* exists, is ignored for precedence, is not a stability signal.

**Yanked or deprecated.** npm: version.deprecated message in the packument (npm deprecate, ranges allowed); unpublish removes. dist-tags are aliases, not versions. SemVer itself defines nothing.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc.1`, `1.0.0-next.0`, `1.0.0-canary.3`, `1.0.0-nightly.20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | identical, ignored in compare |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- npm strips a leading v or = and trims whitespace; loose mode accepts leading zeros.
- Pre-releases only satisfy a range when a comparator has the same [major,minor,patch] and a pre-release, unless includePrerelease.
- Caret on 0.x: ^0.2.3 means >=0.2.3 <0.3.0.
- dist-tags (latest, next) are registry aliases rejected if they parse as a semver range.

**Known gaps**

- Stable filter is a consumer convention; semver.org does not define 'stable'.
- sort() tie order for build-only differences is implementation behaviour.

### SwiftPM (git tags / registry)

`swift`. Ecosystems: `swift`, `swifturl`. purl types: `swift`.

Sources: <https://github.com/swiftlang/swift-tools-support-core/blob/main/Sources/TSCUtility/Version.swift> <https://github.com/swiftlang/swift-package-manager/blob/main/Sources/Basics/Version%2BExtensions.swift> <https://github.com/swiftlang/swift-package-manager/blob/main/Documentation/PackageRegistry/Registry.md>

**Stable release rule.** Stable iff the tag parses (strip one leading lowercase v, allow 2-part) and has no pre-release identifiers. Branch/revision refs are not versions.

**Pre-release.** SemVer -<ident>(.<ident>)* (empty ids tolerated); lower than the release; numeric ids via Int() < alphanumeric. Range bounds without a pre-release exclude pre-releases.

**Build metadata.** +meta accepted, ignored in compare and hash; not a stability signal.

**Yanked or deprecated.** No flag for git tags. Registry (SE-0292) may list a release with a 410 Gone problem document ('removed from the registry'). No deprecation flag found.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc.1`, `510.0.0-prerelease-2024-01-15` |
| branch-ref | `.branch(<name>) / .revision(<sha>)` | `main`, `release/1.0` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | identical, ignored |
| epoch | none |
| postRelease | none |
| prerelease | identical (one hyphenated id is common: prerelease-2024-01-15) |

**Conventions with no SemVer equivalent**

- Tags without and with v and 2-part tags collapse to one version; most specific tag kept.
- Version-specific tags (@swift-5.9 suffix) override plain tags when present.
- from: means up-to-next-major.

**Known gaps**

- Ported from Swift source, not executed in Swift.
- Int() accepts leading zeros and a + sign.

### Terraform Registry (go-version)

`terraform`. Ecosystems: `terraform`. purl types: `terraform?`.

Sources: <https://developer.hashicorp.com/terraform/language/expressions/version-constraints> <https://developer.hashicorp.com/terraform/registry/modules/publish> <https://github.com/hashicorp/go-version>

**Stable release rule.** Stable iff go-version Prerelease() is empty. Pre-releases are selectable only with an exact = constraint.

**Pre-release.** SemVer-like -<pre> (hyphen optional in go-version); lower than the release; constraints other than = never match pre-releases.

**Build metadata.** +meta accepted, ignored; not a stability signal.

**Yanked or deprecated.** Module owner can remove one or all versions via the registry UI. No yank or deprecation flag in the docs read.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.0.0-rc.1`, `1.0.0beta1`, `1.10.0-alpha20241023` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | ignored |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- Release tags must be semver optionally prefixed v; other tags ignored.
- ~> allows only the right-most component to increment.
- Any number of numeric segments and an optional v prefix.

**Known gaps**

- go-version orders 1.0.0-alpha.beta below 1.0.0-alpha (not total for such inputs).
- Provider deprecation flags not found.
- Behaviour is go-version v1.9.0.

### vcpkg (version, version-semver, version-date, version-string)

`vcpkg`. Ecosystems: `vcpkg`. purl types: `vcpkg?`.

Sources: <https://learn.microsoft.com/en-us/vcpkg/users/versioning> <https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json> <https://github.com/microsoft/vcpkg-tool/blob/main/src/vcpkg/versions.cpp>

**Stable release rule.** Stable iff scheme is version or version-semver with no pre-release part, or version-date. version-string is unorderable and its stability cannot be inferred.

**Pre-release.** In relaxed/semver schemes -<ident>(.<ident>)*; lower than the release; shorter numeric section list is lower than longer (1.0 < 1.0.0).

**Build metadata.** +meta parsed, not compared (1.0.0+a and +b compare equal); not a stability signal.

**Post-release.** port-version (#N / port-version field) is a packaging post-release compared after the upstream version.

**Yanked or deprecated.** None: ports are absent from the registry versions database; baselines set a floor. No yank or deprecation flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `1.2.3.4.10-alpha1`, `2.0.1-rc5` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +meta ignored |
| epoch | none |
| postRelease | port-version (#N) |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- Four schemes per manifest, never compared across schemes; version-string only supports equality.
- Resolution picks the LOWEST version satisfying all version>= constraints; overrides pin exact versions.
- version-date is YYYY-MM-DD(.N)* with no calendar validation.

**Known gaps**

- Docs disagree on whether relaxed version allows pre-release; source says yes.
- Ported from C++, not executed.
- 2024-01-15 in relaxed version parses as a pre-release of 2024.

### ZeroVer and unversioned refs

`zerover`. Ecosystems: `zerover`.

Sources: <https://0ver.org/> <https://semver.org/spec/v2.0.0.html#spec-item-4>

**Stable release rule.** Same as the host scheme: stable iff no pre-release. 0.y.z is NOT unstable. HEAD, main, latest, nightly are refs, not versions.

**Pre-release.** As in SemVer when 0.y.z-<pre>; major stays 0.

**Build metadata.** As SemVer: ignored, not a stability signal.

**Yanked or deprecated.** Host ecosystem's mechanism.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `0.88.0-rc.6` |
| branch-ref | `HEAD \| main \| master` | `HEAD`, `main` |
| floating-tag | `latest \| next \| nightly` | `latest`, `nightly` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | as SemVer |
| epoch | none |
| postRelease | none |
| prerelease | as SemVer |

**Conventions with no SemVer equivalent**

- Detection is by history: major==0 for about 95 percent of at least 10 stable releases over at least 2 years.
- Caret on 0.x treats the minor as the breaking slot in Cargo, npm, Julia and pub.

**Known gaps**

- No registry marks ZeroVer; purely heuristic.
- Legacy shapes such as 0.9.8n need the host scheme's comparator.

## Qualifier-based schemes (PEP 440, Maven, RubyGems, conda)

### conda VersionOrder

`conda`. Ecosystems: `conda`, `conda-forge`, `anaconda`, `mamba`, `pixi`. purl types: `conda?`.

Sources: <https://github.com/conda/conda/blob/main/conda/models/version.py> <https://github.com/conda/rattler>

**Stable release rule.** Stable iff no component string other than `post` is present, no `dev`, and no `+local`; bare tags (e.g. `1.1.parallel`) are undecidable from the string, so treat as unstable only if a known pre-release word.

**Pre-release.** No formal syntax: any letter component such as `a`, `b`, `rc`, `alpha`, `beta` (`1.0a1`, `1.2.beta3`) sorts below the release because strings sort below ints; `dev` sorts below everything at its position.

**Build metadata.** `+local` is compared like extra components only when the main versions are equal; an alphabetic local sorts BELOW the plain version (`1.0+abc < 1.0`), a numeric one above; not a stability signal by itself.

**Epoch.** `N!` prefix, default 0, same idea as PEP 440.

**Post-release.** String `post` is greater than any other string at its position (`1.1.post1 > 1.1`); stable.

**Yanked or deprecated.** No yank in the version. Channel mechanisms (repodata `removed`, repodata patches, anaconda.org `broken` label) exist but were not verified.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `component string a\|alpha\|b\|beta\|c\|rc\|pre\|preview with optional digits` | `1.0a1`, `2.3.5rc3`, `1.2.beta3` |
| dev | `component string `dev` with optional digits` | `1.0dev42`, `2.3.5.dev12` |
| local-version | `\+[a-z0-9_.]+` | `1.0+cuda118` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | `+local`, compared (unlike SemVer); conda's separate build string/number is not part of the version. |
| epoch | `N!` prefix, same as PEP 440. |
| postRelease | `post` string, above everything at its position. |
| prerelease | Letters inside components, ordered as case-insensitive strings below ints. |

**Conventions with no SemVer equivalent**

- `-` is accepted and converted to `_` when the version has no underscore, so `1.0-SNAPSHOT` is a valid tag version.
- `1.0rc1 < 1.0.dev1` (dev after a dot is a new component), opposite to PEP 440.
- Letter-suffix versions (openssl `1.0.1a`) sort below `1.0.1`; trailing `_` (`1.0.1_`) is the documented workaround and sorts lowest.
- A component starting with a letter gets an implicit leading 0 (`1.1.a1 == 1.1.0a1`); `1.1 == 1.1.0`.

**Known gaps**

- Ground truth is py-rattler cross-checked with the VersionOrder docstring ladder, not conda's own Python.
- Stability of bare tags is undecidable from the string.
- Registry-level removal mechanisms not verified.

### Coursier / sbt version ordering

`coursier`. Ecosystems: `sbt`, `coursier`, `mill`, `scala-cli`, `bloop`. purl types: `maven?`.

Sources: <https://github.com/coursier/coursier/blob/main/modules/core/shared/src/main/scala/coursier/core/Version.scala>

**Stable release rule.** Unstable iff any tag has level < 0 (dev, unknown tag, alpha, beta, rc, snapshot); tags ga/final/sp/bin and `+build` metadata are stable.

**Pre-release.** Tag levels: dev -6 < unknown -5 < alpha -4 < beta -3 < rc/cr -2 < snapshot -1 < ga/final/empty 0 < sp/bin 1; unknown tags are BELOW alpha (pre-release), unlike Maven.

**Build metadata.** `+...` is parsed as BuildMetadata and ignored in comparison (SemVer-aware); `1.0+build.5 == 1.0`.

**Post-release.** `sp` and `bin` tags sort above the release.

**Yanked or deprecated.** None in the version scheme; resolution uses Maven/Ivy repositories, which have no yank.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `tag alpha\|a\|beta\|b\|rc\|cr, or any unknown tag (level < 0)` | `2.13.0-RC1`, `2.13.0-M5` |
| snapshot | `tag `snapshot`` | `1.0-SNAPSHOT` |
| dev | `tag `dev` (lowest)` | `1.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | `+...` parsed and ignored, like SemVer. |
| epoch | None. |
| postRelease | `sp`/`bin` tags. |
| prerelease | Hyphen tags with fixed levels; unknown tags rank below alpha. |

**Conventions with no SemVer equivalent**

- Used by sbt >= 1.3, Scala CLI, Mill; same family as Maven GenericVersion but with its own tag levels.
- Scala binary-version suffix `_2.13` is part of the artifactId, not the version; Scala milestones `2.13.0-M5` are an unknown tag (below alpha) and still precede RC1.
- `.x`/`.*`/`.+` are treated as max for ranges; `min`/`max` words are special items.

**Known gaps**

- Coined ordering id `custom:coursier`; run via deprecated coursier.core.Version in coursier-core 2.1.26 (the replacement coursier.version.Version was not run).
- Disagrees with Maven on unknown qualifiers (below release here, above in Maven), dev rank and build metadata.
- Older sbt (< 1.3) uses Ivy ordering, see the ivy entry.

### Gradle version ordering

`gradle`. Ecosystems: `gradle`, `ivy`, `ant`. purl types: `maven?`.

Sources: <https://docs.gradle.org/current/userguide/dependency_versions.html> <https://github.com/gradle/gradle/blob/master/platforms/software/dependency-management/src/main/java/org/gradle/api/internal/artifacts/ivyservice/ivyresolve/strategy/StaticVersionComparator.java>

**Stable release rule.** Same qualifier word list as maven: unstable iff -SNAPSHOT (status integration), timestamped snapshot, or a conventional pre-release word (alpha, beta, milestone, m, rc, dev, ea, preview, nightly); final/ga/release/sp are stable.

**Pre-release.** No pre-release syntax: split on `. - _ +` and digit/letter transitions; `dev` is lowest, unknown strings (ASCII, case-sensitive) next, then rc < snapshot < final < ga < release < sp; any version with an extra string part is BELOW the bare version.

**Build metadata.** None: `+` is a separator, so `1.0+build` has a lower string part and sorts BELOW 1.0.

**Post-release.** `sp` ranks highest among string parts, but `1.0-sp1 < 1.0` because an extra non-numeric part is lower than no part.

**Yanked or deprecated.** None in the version scheme; Gradle component `status` (integration for -SNAPSHOT, release otherwise, default scheme integration < milestone < release) comes from metadata, not a yank flag.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| snapshot | `-SNAPSHOT suffix or -\d{8}\.\d{6}-\d+$` | `1.0-SNAPSHOT` |
| prerelease | `alpha\|beta\|milestone\|m\d\|rc string part` | `1.0-rc1`, `1.0-RC-1`, `1.0-M1` |
| dev | `string part `dev` (lowest special word)` | `1.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | None; `+` is just a separator. |
| epoch | None. |
| postRelease | `sp` (only relative to other string parts). |
| prerelease | Any extra string part; only dev/rc/snapshot/final/ga/release/sp carry fixed ranks. |

**Conventions with no SemVer equivalent**

- Trailing zero is significant: `1.0 < 1.0.0`.
- Special words are case-insensitive but unknown strings compare case-sensitively (`1.A < 1.B < 1.a`).
- Comparing two different-case spellings of one special word returns 0 immediately: `1.0-RC1 == 1.0-rc9`.
- Dynamic versions `1.+`, `latest.integration`, `latest.release`.

**Known gaps**

- Gradle docs say sp/final/ga/release are 'higher than any other string part' but versus a bare version they sort lower (verified by running the real source).
- Differs from Maven on `1.0 == 1.0.0`, `-final`, `-sp1`, `+build`, `dev` rank; Maven docs note `[1.0,2.0)` is interpreted differently in Gradle.
- Stability classes are convention; Gradle itself only exposes status.

### Apache Ivy latest-revision

`ivy`. Ecosystems: `ivy`, `ant`.

Sources: <https://ant.apache.org/ivy/history/latest-milestone/settings/latest-strategies.html> <https://github.com/apache/ant-ivy/blob/master/src/java/org/apache/ivy/plugins/latest/LatestRevisionStrategy.java>

**Stable release rule.** No engine-level stable flag; apply the maven word list (snapshot, alpha, beta, rc, milestone, dev) to string parts; descriptor status `release` is the registry-level signal.

**Pre-release.** No syntax: parts split on `. _ - +` and letter/digit boundaries; only `dev` (-1), `rc` (1) and `final` (2) are special; unknown strings (0) sort lexically, `1.0-dev1 < 1.0-alpha1 < 1.0-rc1 < 1.0`.

**Build metadata.** None: `+` is a separator and the following word is an ordinary string part.

**Post-release.** None; `sp`, `ga`, `snapshot` and `release` are not special, and `1.0-final < 1.0`.

**Yanked or deprecated.** None in the version scheme; Ivy descriptors carry a `status` (integration/milestone/release) used by latest.<status> selectors.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| snapshot | `-SNAPSHOT string part (not special in Ivy ordering)` | `1.0-SNAPSHOT` |
| prerelease | `dev\|alpha\|beta\|rc\|milestone string part` | `1.0-rc1`, `1.0-dev1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | None. |
| epoch | None. |
| postRelease | None. |
| prerelease | Any extra string part; dev < unknown < rc < final. |

**Conventions with no SemVer equivalent**

- Algorithm is inspired by PHP version_compare; 1.0 < 1.0.0 (extra numeric part is higher).
- `1.0-RC1 == 1.0-rc2` short-circuit (same code lineage as Gradle).
- Custom special words can be configured per Ivy settings; defaults used here.

**Known gaps**

- Coined ordering id `custom:ivy` because no listed id fits (closest is gradle: same dev/rc/final lineage but Gradle adds snapshot/ga/release/sp).
- No purl type known for Ivy modules; they are Maven-layout artifacts.
- Ivy descriptor `status` semantics were not verified beyond the Gradle docs.

### Maven ComparableVersion

`maven`. Ecosystems: `maven`, `java`, `jvm`, `kotlin`, `scala`, `clojars`, `clojure`, `leiningen`, `groovy`, `android`, `maven-central`, `sbt`, `coursier`, `mill`, `scala-cli`, `bloop`. purl types: `maven?`.

Sources: <https://maven.apache.org/pom.html#version-order-specification> <https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java>

**Stable release rule.** Unstable iff a token matches (?i)(^|[.\-_])(alpha|beta|milestone|rc|cr|snapshot|a\d|b\d|m\d), or `-YYYYMMDD.HHMMSS-N` timestamped snapshot, or by convention dev/ea/preview/pre/nightly/canary; stable otherwise (ga, final, release, sp, -N, jre, android, incubating).

**Pre-release.** Qualifiers alpha < beta < milestone < rc (= cr) < snapshot, all below the release; a/b/m are shorthand only when directly followed by a digit; case-insensitive.

**Build metadata.** None: `+` is an ordinary character folded into a qualifier string (`1.0+build.5` sorts after 1.0); not a stability signal.

**Post-release.** `sp` (service pack) and a numeric sublist `1.0-1` sort after the release; `ga`, `final`, `release` equal the bare release.

**Yanked or deprecated.** None on Maven Central (components are not removed or modified; no deprecated/deleted flag). Closest: POM `distributionManagement/relocation`.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `alpha\|beta\|milestone\|rc\|cr, or a\|b\|m followed by a digit, as a qualifier token` | `1.0-alpha-1`, `1.0-RC1`, `1.0-M1` |
| snapshot | `-SNAPSHOT suffix (case-insensitive) or timestamped -\d{8}\.\d{6}-\d+$ (sorts AFTER the release)` | `1.0-SNAPSHOT`, `1.0-20240101.123456-1` |
| dev | `conventional unknown qualifier dev/ea/preview/pre (sorts AFTER the release in Maven)` | `1.0-dev`, `1.0-ea`, `1.0-preview` |
| nightly | `conventional unknown qualifier nightly/canary` | `1.0-nightly`, `1.0-nightly-20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | None; `+` is part of a qualifier string. |
| epoch | None. |
| postRelease | `sp`, `ga`/`final`/`release` (equal to bare), numeric sublist `-1`. |
| prerelease | Fixed-rank qualifiers alpha/beta/milestone/rc/snapshot; SemVer 2.0.0 precedence is explicitly not followed. |

**Conventions with no SemVer equivalent**

- Trailing zeros and ga/final/release are trimmed so `1 == 1.0 == 1.0.0 == 1.0-ga`.
- `.qualifier = -qualifier < -number < .number`; list/sublist nesting is created by `-` and by letter/digit transitions.
- Unknown qualifiers sort after `sp`, lexically; so `1.0-dev`, `1.0-ea`, `1.0-nightly` are NEWER than 1.0 although semantically pre-releases.
- Timestamped snapshot `1.0-20240101.123456-1` is a numeric sublist and sorts after release 1.0.
- Version ranges `[1.0,2.0)` include `2.0-rc1`; LATEST/RELEASE are meta-versions, not versions (`ComparableVersion("RELEASE")` equals 0).
- Scala `_2.13` artifact suffix is part of the artifactId, not the version; Guava-style `-jre`/`-android` flavours are stable.

**Known gaps**

- Three comparators exist: maven-artifact ComparableVersion 3.x (primary here), Maven 4 master ComparableVersion (differs on ~0.1% of realistic pairs, e.g. `2.0-1` vs `2-3`, and gives `1-sp-1 > 1-ga-1` contrary to the published spec) and maven-resolver GenericVersion (treats `1.0-1 == 1.0.1`, `1-1 == 1.1`, and orders timestamped snapshots after 1.0.1).
- Stability of unknown qualifiers (dev, ea, preview, nightly) is convention, not spec; `incubating` treated as stable.
- No registry yank/deprecation flag; Clojars policy not checked.

### PEP 440 (PyPI, pip)

`pep440`. Ecosystems: `pypi`, `pip`, `python`, `pep440`, `uv`, `poetry`. purl types: `pypi?`.

Sources: <https://packaging.python.org/en/latest/specifications/version-specifiers/> <https://peps.python.org/pep-0440/> <https://github.com/pypa/packaging/blob/main/src/packaging/version.py>

**Stable release rule.** Parse with PEP 440; stable iff pre is None and dev is None and local is None (post and epoch are fine); unparseable strings are skipped; skip yanked files unless exactly pinned.

**Pre-release.** Normalised `aN`, `bN`, `rcN` (spellings alpha, beta, c, pre, preview accepted, separators . - _ optional) and `.devN`; all sort before the final, with `.devN` below `aN` below `bN` below `rcN` below the final.

**Build metadata.** `+label` is a local version: it IS compared (sorts after the same public version; numeric segments above alphabetic), PyPI rejects uploads containing it, so treat it as a non-public/unstable signal.

**Epoch.** `N!` prefix, integer, implicit 0; a higher epoch outranks every lower-epoch version (`1!1.0 > 2024.1`).

**Post-release.** `.postN` (also `-N`, `rev`, `r`); sorts after the final and is stable.

**Yanked or deprecated.** PEP 592 yank is per file: `data-yanked` attribute in the simple HTML API, `files[].yanked` (bool or reason string) in the PEP 691 JSON API, `releases[v][i].yanked`/`yanked_reason` in the Warehouse JSON API. Project-level status (PEP 792) lives in simple API `project-status`.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(a\|b\|rc)\d+ after normalisation; raw [._-]?(alpha\|a\|beta\|b\|preview\|pre\|c\|rc)[._-]?\d*` | `1.0rc1`, `1.0a1`, `2.0.0-rc.1` |
| dev | `\.dev\d+ (raw [._-]?dev[._-]?\d*), also on post and pre releases` | `1.0.dev1`, `1.0.post1.dev2` |
| local-version | `\+[a-z0-9]+([._-][a-z0-9]+)*` | `1.0+abc`, `1.0.0-alpha+exp.sha.5114f85` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | Local version `+label`, but it participates in ordering unlike SemVer build metadata. |
| epoch | No SemVer equivalent; epoch `N!` overrides all other components. |
| postRelease | No SemVer equivalent; `.postN` sorts after the final. |
| prerelease | Only aN/bN/rcN and .devN; arbitrary SemVer identifiers (`-alpha.beta`, `-x.7.z.92`) are invalid; `-rc.1` normalises to rc1. |

**Conventions with no SemVer equivalent**

- Trailing zeros are insignificant (`1.0 == 1.0.0`); `v` prefix, case and the separators `. - _` normalise away.
- `1.0-1` is a post-release (stable, newer than 1.0), not a prerelease.
- Alternate spellings (alpha, beta, c, pre, preview, rev, r) normalise to a, b, rc, post.
- Dev releases of pre/post releases exist (`1.0a1.dev1`, `1.0.post1.dev1`).
- Specifier semantics exclude pre-releases unless asked (`>=1.0` skips `1.1a1`); `>V` excludes post-releases of V.
- CalVer (`2024.1.15`) is valid.

**Known gaps**

- Yanked cannot be derived from the string; the consumer must carry the registry flag.
- Local versions are classed unstable by policy; `packaging.is_prerelease` is False for them.
- Legacy non-conforming strings (`1.0-SNAPSHOT`, `1.0.RELEASE`) are unparseable since packaging 22.0; old PyPI data may contain them.
- conda uses a different comparator (see conda entry).

### RubyGems Gem::Version

`rubygems`. Ecosystems: `rubygems`, `gem`, `ruby`, `bundler`. purl types: `gem?`.

Sources: <https://guides.rubygems.org/specification-reference/> <https://github.com/rubygems/rubygems/blob/master/lib/rubygems/version.rb>

**Stable release rule.** Stable iff Gem::Version.new(v).prerelease? is false, i.e. no ASCII letter anywhere in the string and no `-`; strip the platform suffix first; skip versions marked yanked.

**Pre-release.** Any ASCII letter in the version makes it a prerelease (`1.0.0.pre`, `.rc1`, `.beta.2`); letter segments compare below numeric ones, so a prerelease sorts below its release, ordered alphabetically (case-sensitive) among letter words.

**Build metadata.** None: `+` is invalid and raises; a `-` is rewritten to `.pre.`, so `1.0.0-rc1` becomes `1.0.0.pre.rc1` (a prerelease).

**Post-release.** None: `post` is just a letter so `1.0.0.post1` is a PRERELEASE and sorts BELOW 1.0.0.

**Yanked or deprecated.** Yank = DELETE /api/v1/gems/yank; the version vanishes from /api/v1/versions and /info, GET /api/v2/rubygems/<g>/versions/<v> returns 404, and the compact index /versions file gets an append-only `<gem> -<version> <md5>` line (leading `-`). JSON `yanked` boolean exists on /api/v1/gems/<g>.json.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `[a-zA-Z] anywhere in the version, or `-` (rewritten to .pre.)` | `1.0.0.pre`, `1.0.0.rc1`, `1.0.0-rc1` |
| dev | `letter segment `dev` (no special rank, alphabetical)` | `2.0.0.dev` |
| snapshot | `letter segment `snapshot`` | `1.0.0.snapshot` |
| nightly | `letter segment `nightly`` | `1.0.0.nightly.20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | None (`+` invalid). |
| epoch | None. |
| postRelease | None; `post` is a prerelease letter. |
| prerelease | Any letter-bearing segment; `-` becomes `.pre.`; no phase semantics (alphabetical). |

**Conventions with no SemVer equivalent**

- Trailing zeros are ignored, also before the first letter (`1.a == 1.0.a == 1.0.0.a`).
- Platform is a separate field (`name-version-platform.gem`; compact index writes VERSION-PLATFORM split at the first dash): x86_64-linux, arm64-darwin, java, x64-mingw-ucrt, x86-mswin32-60, etc.; never part of the Gem::Version.
- Feeding `1.3.1-java` to Gem::Version yields prerelease `1.3.1.pre.java`; `1.0.0-x86_64-linux` raises.
- Prerelease word order is alphabetical (alpha < beta < dev < post < pre < rc), so `dev` builds outrank `beta`.
- Empty/nil version is `0`; blank whitespace is stripped; Rational Versioning (3 integers) is recommended.

**Known gaps**

- Reason tokens (dev, snapshot, nightly, milestone) are assigned from the letter text in vectors; RubyGems only knows prerelease.
- Whether rubygems.org permits re-pushing a yanked version number was not verified.
- Run on Ruby 4.0.7 / RubyGems 4.0.20 only; the sort_key fast path was not diffed against older releases.

## Operating system and distribution packages

### Alpine apk (digits, letter, suffixes, ~hash, -rN)

`alpine`. Ecosystems: `alpine`, `alpaquita`, `bellsoft hardened containers`, `minimos`. purl types: `apk`.

Sources: <https://gitlab.alpinelinux.org/alpine/abuild/-/blob/master/APKBUILD.5.scd> <https://github.com/alpinelinux/apk-tools/blob/v3.0.8/src/version.c> <https://github.com/alpinelinux/apk-tools/blob/v3.0.8/test/unit/version.data>

**Stable release rule.** Version must pass apk_version_validate (otherwise unparseable). It is UNSTABLE iff it contains _alpha, _beta, _pre or _rc (regex _(alpha|beta|pre|rc)\d*), a snapshot suffix _(git|hg|cvs|svn)\d*, or a ~<hex> commit marker. -rN (pkgrel, including security bumps), _p<N>, and a trailing letter are STABLE.

**Pre-release.** _alpha, _beta, _pre, _rc (+ optional number): strictly below the bare version; ladder alpha < beta < pre < rc < release.

**Build metadata.** None. ~<hex> commit hash (apk-tools 3 only) participates in ordering and sorts above the bare version.

**Epoch.** None.

**Post-release.** _p<N>, _cvs, _svn, _git, _hg suffixes and a single trailing letter sort above the bare version (cvs < svn < git < hg < p < letter).

**Yanked or deprecated.** No in-band flag. Packages are deleted from a repository branch (edge, vX.Y); secdb lists fixed versions as pkgver-rN.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `_(alpha\|beta\|pre\|rc)\d*` | `1.2.3_rc1-r0`, `1.2.3_beta2` |
| git-snapshot | `_(git\|hg\|cvs\|svn)\d*` | `1.2.3_git20240101-r0`, `1.2.3_svn1234` |
| git-snapshot | `~[0-9a-f]+ (v3 only)` | `1.2.3~abcdef0-r0` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none (~hash is the nearest, but ordered) |
| epoch | none |
| postRelease | _p<N>, _git/_svn/_cvs/_hg, trailing letter |
| prerelease | _alpha/_beta/_pre/_rc suffix |

**Conventions with no SemVer equivalent**

- -rN is pkgrel (APKBUILD first release is 0); 1.0 < 1.0-r0 < 1.0-r1 in C apk-tools.
- A numeric component with a leading zero switches to raw string comparison (1.01 < 1.1, 1.0 < 1.00).
- Suffix ladder: alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p.
- Suffixes may chain (1.1.3_pre_p2, 1.0_rc1_git20240101-r3).
- Snapshot pkgver convention <last-release>_git<YYYYMMDD>.
- Release branches (edge, testing, v3.xx) are channels, not version syntax.

**Known gaps**

- apk-tools 2.14.x differs: no ~hash and a different leading-zero path; which Alpine release ships which apk-tools was not verified.
- Compare tokenises invalid input up to the bad token; callers must validate first.
- Alpaquita, BellSoft Hardened Containers and MinimOS are mapped here by assumption.

### Android OSV version (<branch>[L][-qprN][-next]:<SPL>)

`android`. Ecosystems: `android`.

Sources: <https://ossf.github.io/osv-schema/> <https://source.android.com/docs/setup/reference/build-numbers> <https://source.android.com/docs/security/bulletin/asb-overview> <https://developer.android.com/guide/topics/manifest/uses-sdk-element> <https://developer.android.com/studio/publish/versioning>

**Stable release rule.** Version must match ^\d+(\.\d+)?L?(-qpr\d+)?(-next)?(:\d{4}-\d{2}-\d{2}|:0)?$ (else unparseable: build IDs, AOSP tags, three-component marketing versions). UNSTABLE iff it ends the branch part with -next; bare branches, L, -qprN and any :SPL are STABLE.

**Pre-release.** No documented syntax. The -next suffix on a branch (13-next) is inferred to be an unreleased development track.

**Build metadata.** None in OSV strings; AOSP build IDs (PVBB.YYMMDD.bbb[.Cn]) are a separate identifier kind.

**Epoch.** None.

**Post-release.** Security patch level after the colon (:YYYY-MM-DD) is the fix granularity within a branch; -qprN and L are later platform releases within a major.

**Yanked or deprecated.** None in the version string. Branches reach end of life; apps are superseded by a higher versionCode, which can never be reused on Google Play.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| dev | `-next after the branch part` | `13-next`, `16-qpr2-next:2025-12-01`, `12L-next` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | :SPL date, -qprN, L |
| prerelease | -next (inferred) |

**Conventions with no SemVer equivalent**

- OSV composite <branch>:<SPL>: introduced '<branch>:0', fixed '<branch>:<SPL>', versions list holds the bare branch.
- 12L is Android 12.1 (API 32); 16-qprN are quarterly platform releases (API 36.N in the build table).
- API level is a single integer that cannot be derived from the marketing version; the manifest cannot express minor API levels.
- App versionCode is a monotonically increasing positive integer (max 2100000000); versionName is display-only.
- Kernel advisories use package name :linux_kernel:<SoC vendor>.

**Known gaps**

- No reference comparator exists; the order is derived from OSV data and Android docs.
- The meaning of -next is inferred, not documented.
- SPL -01/-05/-06 semantics are not defined on the bulletin overview page.
- Build-ID and AOSP-tag ordering is only meaningful within a platform branch and is not implemented.

### Arch pacman/libalpm (epoch:pkgver-pkgrel)

`arch`. Ecosystems: `arch`, `archlinux`, `cachyos`, `manjaro`, `endeavouros`, `aur`. purl types: `alpm`.

Sources: <https://man.archlinux.org/man/vercmp.8> <https://man.archlinux.org/man/PKGBUILD.5> <https://wiki.archlinux.org/title/VCS_package_guidelines> <https://gitlab.archlinux.org/pacman/pacman/-/blob/master/lib/libalpm/version.c>

**Stable release rule.** No version syntax distinguishes stable, so classify by convention on pkgver (pkgrel and epoch removed): UNSTABLE iff it has a delimited pre-release word (alpha|beta|rc|pre|preview|prerelease|milestone|candidate)\d*, a VCS form (r\d+\.[0-9a-f]{7,}, \.r\d+\.g[0-9a-f]{7,}, \+r\d+\+g[0-9a-f]{7,}, (git|svn|hg|bzr|cvs|darcs) + digits/hex), or a dev/nightly/snapshot word. pkgrel bumps (-2, -1.1), epochs, date versions and single patch letters (1.1.1k) are STABLE.

**Pre-release.** No syntax. A trailing alpha attached directly to a number (1.0rc1) sorts below 1.0 by the trailing-alpha rule; with any separator (1.0_rc1, 1.0.rc1, 1.0~rc1) it sorts ABOVE 1.0.

**Build metadata.** None. '+' and '~' are plain separators.

**Epoch.** epoch= in PKGBUILD, epoch: prefix, positive integer default 0, dominates.

**Post-release.** Extra segment (1.0.1, 1.0.a) sorts above the base.

**Yanked or deprecated.** No in-band flag. Package removed from the sync repo; old builds in the Arch Linux Archive; AUR packages can be deleted or orphaned.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `delimited alpha\|beta\|rc\|pre words in pkgver` | `1.2.3rc1-1`, `1.2.3_rc1-1`, `1.2.3.beta2-1` |
| git-snapshot | `r<count>.<sha7+>; <tag>.r<N>.g<sha7+>; +git<date>` | `r1234.abcdef0-1`, `1.2.3.r15.g1a2b3c4-1`, `1.2.3+git20240101-1` |
| dev | `delimited words dev\|snapshot` | `1.2.3.dev0-1` |
| nightly | `delimited word nightly` | `20240101.nightly-1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | epoch |
| postRelease | extra segment |
| prerelease | none (trailing-alpha accident) |

**Conventions with no SemVer equivalent**

- pkgver forbids hyphen, colon, slash, whitespace; upstream 1.0-rc1 must be respelled and the spelling changes ordering.
- pkgrel is N or N.M; compared only when both versions have one (1.5 == 1.5-1).
- VCS packages carry -git/-svn/-hg/-bzr/-cvs/-darcs in the package NAME and generate pkgver via git describe | sed or r<count>.<sha>.
- Separator-run length differs => shorter run is older (1.0..1 > 1.0.1).
- Repositories (core, extra, *-testing, *-staging) are channels, not version syntax.

**Known gaps**

- Pre-release and snapshot classification is purely heuristic.
- libalpm vercmp is rpm 4.8.1-derived: do not reuse the rpm scheme (no ~ or ^).
- Arch packaging-guideline text on pre-release spelling was not retrieved.
- Manjaro/CachyOS/EndeavourOS rebuild markers not verified.

### Bitnami X.Y.Z[-revision] (revision-aware SemVer)

`bitnami`. Ecosystems: `bitnami`. purl types: `bitnami`.

Sources: <https://github.com/aquasecurity/trivy/discussions/5622> <https://github.com/bitnami/go-version/blob/main/pkg/version/version.go> <https://ossf.github.io/osv-schema/> <https://blog.bitnami.com/2024/02/debian-12-is-now-base-operating-system.html>

**Stable release rule.** Version must be exactly three numeric components plus optional -revision and +meta (SemVer regex without leading zeros), else unparseable. The revision slot is a REBUILD counter: -N, -rN and -<distro>-<release>-rN (7.2.4-debian-12-r5) are STABLE. UNSTABLE iff the revision part contains a delimited pre-release word (alpha|beta|rc|pre|preview|prerelease|milestone|candidate)\d*, nightly, dev|devel|snapshot|canary, or a VCS word.

**Pre-release.** Not supported as SemVer pre-release: the '-' slot is a REVISION, so 1.0.0-rc1 sorts ABOVE 1.0.0. Named pre-releases are detected by word only.

**Build metadata.** +meta is ignored for ordering (1.0.0+a == 1.0.0+b).

**Epoch.** None.

**Post-release.** The revision itself: 2.4.58 < 2.4.58-1 < 2.4.58-2 < 2.4.59; compared as SemVer pre-release identifiers (numeric before alphanumeric, lexical for alphanumerics).

**Yanked or deprecated.** No flag in the version. Old images moved to the bitnamilegacy namespace (no longer updated); rolling tags move on rebuild, immutable tags are fixed.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `delimited alpha\|beta\|rc\|pre words in the revision part` | `1.0.0-rc1`, `1.0.0-beta.2`, `1.0.0-rc.1-debian-12-r1` |
| dev | `words dev\|devel\|snapshot\|canary in the revision part` | `1.0.0-snapshot` |
| nightly | `word nightly in the revision part` | `1.0.0-nightly` |
| git-snapshot | `git\|svn\|hg\|bzr\|cvs + digits/hex in the revision part` | `1.0.0-git20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +meta (ignored) |
| epoch | none |
| postRelease | -revision (-N, -rN) |
| prerelease | none (the '-' slot is a post-release revision) |

**Conventions with no SemVer equivalent**

- A plain SemVer comparer ranks 2.4.58-1 below 2.4.58 (real Trivy false positive); Bitnami's comparer ranks any revision above none.
- Container tags: rolling 6.4.3 vs immutable 6.4.3-debian-12-r10; rN increments per rebuild and resets to r0 when the base OS changes (debian-11-r4 -> debian-12-r0).
- Revision r5 vs r10 in a container tag is ONE alphanumeric identifier and compares lexically (r5 > r10).
- Two- or four-component versions are invalid for the comparer.
- Helm chart versions are the chart's own SemVer, independent of appVersion.

**Known gaps**

- No official Bitnami document defines the grammar; sources are maintainer statements in the Trivy thread, tag docs via summary, and the go-version code.
- Sampled OSV Bitnami data (redis, 50 advisories) used plain SemVer ranges without revisions.
- Legacy-namespace move seen only via search summary and Docker Hub listing.

### Debian dpkg (epoch:upstream-revision)

`debian`. Ecosystems: `debian`, `ubuntu`, `kali`, `raspbian`, `raspberry pi os`, `linuxmint`, `mint`, `devuan`, `echo`, `pureos`, `tails`. purl types: `deb`.

Sources: <https://www.debian.org/doc/debian-policy/ch-controlfields.html#version> <https://manpages.debian.org/unstable/dpkg-dev/deb-version.7.en.html> <https://ubuntu.com/project/docs/how-ubuntu-is-made/concepts/version-strings/> <https://github.com/guillemj/dpkg/blob/main/lib/dpkg/version.c>

**Stable release rule.** A version is STABLE unless, after deleting the stable tilde tokens ~bpo\d+, ~deb\d+u\d+, ~\d{2}\.\d{2}(\.\d+)*, ~ubuntu\d[\d.]*, ~esm\d*, ~backport\d*, it still contains a '~', OR contains a pre-release word (?<![A-Za-z])(alpha|beta|rc|pre|preview|prerelease|milestone|candidate)([._-]?\d+)?(?![A-Za-z]), OR a VCS/nightly/dev marker (git|svn|hg|bzr|cvs|darcs)(hex|digits)|nightly|dev|snapshot, OR a +YYYYMMDD date snapshot. Security/stable rebuild suffixes (-1ubuntu0.22.04.1, +deb11u1, +b1, +nmu1, +esm1, +dfsg, +really2.2-1, -0.1, kaliN, +rpiN) and stable backport tildes (~bpo11+1, ~deb12u1, ubuntu0~16.04.4, ubuntu2~22.04.1) are STABLE.

**Pre-release.** Tilde: 1.0~rc1 sorts before 1.0 (and 1.0~~ < 1.0~~a < 1.0~ < 1.0). A bare 1.0rc1 is NOT ordered as a pre-release: it sorts after 1.0.

**Build metadata.** None. +b1 (binNMU), +dfsg, +git2024... are ordinary characters and take part in ordering ('+' sorts after end of string).

**Epoch.** Integer before the first colon, default 0, dominates everything (2:0.1 > 1:9.9).

**Post-release.** Any +suffix on upstream or revision (+b1, +nmu1, +deb12u1, +really2.2, +dfsg) sorts above the bare version.

**Yanked or deprecated.** No in-band flag. Removal from a suite by ftpmaster (archive); fixed status lives in the Debian Security Tracker; history in snapshot.debian.org.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `~ not followed by a stable backport token (bpo, debNuN, YY.MM, ubuntuN, esm); or words alpha\|beta\|rc\|pre\|preview as delimited tokens` | `1.0~rc1-1`, `2.0rc1-1`, `1.0~beta2+dfsg-1` |
| git-snapshot | `(git\|svn\|hg\|bzr\|cvs\|darcs) followed by digits/hex, or .g<7+hex> at end` | `1.0+git20240101.abc1234-1`, `1.0~git20240101-1`, `0.9+svn1234-2` |
| snapshot | `+YYYYMMDD / ~YYYYMMDD date stamp (heuristic)` | `1.0+20240101-1` |
| nightly | `delimited word nightly` | `1.0+nightly20240101-1` |
| dev | `delimited words dev\|devel\|snapshot\|canary` | `2.0.0~dev1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none (+bN, +dfsg participate in ordering) |
| epoch | epoch: prefix |
| postRelease | +suffix (+bN, +debNuM, +really) |
| prerelease | ~ (tilde) in upstream_version; sorts before the release |

**Conventions with no SemVer equivalent**

- Revision is everything after the LAST hyphen; absent revision equals revision 0 and sorts below any non-zero revision (1.0 < 1.0-1).
- binNMU +bN (2.9-3 -> 2.9-3+b1); source version unchanged, binary version higher.
- NMU: native +nmuN, non-native revision -X.Y (1.5-3 -> 1.5-3.1, 1.0-0.1).
- Stable security/point updates +debXuN (X = release major); same-upstream uploads to stable may use ~debXuN.
- Backports ~bpoX+N sort below the same version without the tilde and above ~bpo(X-1).
- +really rollback without epoch bump (2.3+really2.2-1); never use an epoch for rollbacks.
- Ubuntu: ubuntuN (delta), buildN (no-change rebuild), maysync1 < ubuntu1 < willsync1, SRU ubuntu0.N and ubuntu0.<YY.MM>.N, backport ~<YY.MM>.N, +esmN (Pro ESM).
- Repacked upstream tarballs +dfsg / +ds / +repack are part of upstream_version and stable.
- Suites (stable, testing, unstable, *-backports, *-proposed-updates) are archive channels, never in the version string.

**Known gaps**

- +YYYYMMDD date-snapshot detection and bare rc/beta words without tilde are heuristics, not Policy rules.
- dpkg treats a non-digit start or odd characters as warnings, not errors; vectors mark them orderable=true.
- Mint +mintN and Kali kaliN suffix forms were not verified against distro documents.
- Developers Reference text on non-native NMU numbering (-1.1) was truncated in the fetch.

### Gentoo ebuild version (PMS)

`gentoo`. Ecosystems: `gentoo`, `portage`.

Sources: <https://projects.gentoo.org/pms/latest/pms.html> <https://devmanual.gentoo.org/ebuild-writing/file-format/index.html> <https://github.com/gentoo/portage/blob/master/lib/portage/versions.py>

**Stable release rule.** Version must match ^[0-9]+(\.[0-9]+)*[a-z]?(_(alpha|beta|pre|rc|p)[0-9]*)*(-r[0-9]+)?$ (else unparseable). UNSTABLE iff it has _(alpha|beta|pre|rc)\d*, a date snapshot _p\d{8}, or a live marker component 9999+ ((^|\.)9{4,}(?=$|\.|[a-z_-])). -rN (Gentoo revision) and _p<N> patch releases are STABLE. Real 'stable' is KEYWORDS, not the version string.

**Pre-release.** _alpha, _beta, _pre, _rc suffixes (+ number); ladder alpha < beta < pre < rc < release < _p.

**Build metadata.** None.

**Epoch.** None.

**Post-release.** _p<N> upstream patch release and a trailing letter (1.0a) sort above the bare version.

**Yanked or deprecated.** Not in the version. package.mask and last-rites removal from the tree; GLSA for security; stability is the per-arch KEYWORDS entry (amd64 vs ~amd64).

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `_(alpha\|beta\|pre\|rc)\d*` | `1.2.3_rc1-r1`, `1.2.3_pre20240101` |
| snapshot | `_p\d{8} (devmanual last-release_pYYYYMMDD)` | `1.2.3_p20240101` |
| snapshot | `live ebuild: 9999 or 9{4,} as a version component` | `9999`, `1.2.9999`, `99999999` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | _p<N>, trailing letter |
| prerelease | _alpha/_beta/_pre/_rc suffix |

**Conventions with no SemVer equivalent**

- -rN is a Gentoo-side revision; absent equals -r0 (1.0 == 1.0-r0).
- A numeric component with a leading zero compares as a decimal fraction (1.01 < 1.1); more components wins (1.0 < 1.0.0).
- A trailing letter is compared after all numeric components (1.0b < 1.0.0).
- Suffixes chain (1.0.0_alpha_rc1); if one side has extra suffixes the first extra _p makes it greater, any other makes it smaller.
- Snapshots: <last>_pYYYYMMDD (post) or <upcoming>_preYYYYMMDD (pre); live ebuilds use 9999 or 99999999.
- _git/_svn/_cvs/_hg suffixes are not Gentoo syntax.

**Known gaps**

- Only the first 100,000 of 220,673 characters of the PMS page were read.
- _p\d{8} may misflag a genuine 8-digit patch counter.
- Stability via KEYWORDS and package.mask is outside the version string.
- No purl type is known for Gentoo.

### Homebrew formula version (Version/PkgVersion)

`homebrew`. Ecosystems: `homebrew`, `brew`. purl types: `brew`.

Sources: <https://ossf.github.io/osv-schema/> <https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/version.rb> <https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/pkg_version.rb>

**Stable release rule.** After removing the formula revision suffix _\d+$, UNSTABLE iff the version contains a pre-release token (?<![A-Za-z])(alpha|beta|pre|rc)\d*(?![A-Za-z]) or (?<=\d)[ab]\d+, or equals HEAD / HEAD-<sha>, or has a dev|devel|snapshot|canary|nightly word or VCS word. _N revision, pN and .postN are STABLE.

**Pre-release.** Tokens alpha[N]|aN, beta[N]|bN, pre[N], rc[N] (case-insensitive, any separator); ladder alpha < beta < pre < rc < release.

**Build metadata.** None; all tokens are compared.

**Epoch.** Formula version_scheme (integer, compared before version); not part of the version string.

**Post-release.** pN and .postN tokens sort above the release; unknown words (-dev, -nightly) also sort above.

**Yanked or deprecated.** Not in the version. Formula DSL deprecate!/disable! or removal from the tap; versioned formulae (name@N) hold older streams.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `alpha\|beta\|pre\|rc tokens, aN, bN` | `1.2.3rc1`, `2.0.0-beta.2`, `2.0.0a1` |
| branch-ref | `HEAD or HEAD-<commit>` | `HEAD`, `HEAD-abc1234` |
| dev | `words dev\|devel\|snapshot\|canary` | `1.2.3-dev` |
| nightly | `word nightly` | `1.2.3-nightly` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | version_scheme (Formula attribute) |
| postRelease | pN / .postN tokens |
| prerelease | alpha/beta/pre/rc tokens |

**Conventions with no SemVer equivalent**

- _N suffix is the formula revision (rebuild), compared after the version; omitted when 0; carried by OSV and pkg:brew purls.
- name@N selects a version stream in the NAME.
- HEAD versions are equal to each other and greater than every release.
- 1 == 1.0 == 1.0.0 (zero tokens equal the absent token).
- Bottle rebuild numbers are not part of the version.

**Known gaps**

- Unknown words (-dev, -nightly) sort above the release; do not infer stability from ordering.
- a1/b1 tokens may misread a patch letter plus build number.
- version_scheme is not in the version string; string-only comparison cannot reproduce Formula-level order.
- Casks are not covered.

### Linux kernel mainline (x.y[.z[.w]][-rcN])

`linux`. Ecosystems: `linux`.

Sources: <https://docs.kernel.org/process/2.Process.html> <https://ossf.github.io/osv-schema/>

**Stable release rule.** Version (optional leading v) must match ^v?\d+\.\d+(\.\d+){0,2}(-rc\d+)?$ or ^next-\d{8}$. UNSTABLE iff it ends in -rc\d+ or is a linux-next tag next-YYYYMMDD. x.y, x.y.z and x.y.z.w are STABLE. Distro kernel strings (6.1.0-18-amd64, 5.14.0-362.el9) are not this scheme.

**Pre-release.** -rcN (6.0-rc1 .. rc7) sorts before the release it precedes and after the previous release; stable-queue 6.1.55-rc1 sorts before 6.1.55.

**Build metadata.** None for kernel.org versions; distros append their own (-generic, +deb) which belong to the distro scheme.

**Epoch.** None.

**Post-release.** Stable updates add a third component (6.1.55); legacy trees use four (2.6.32.71).

**Yanked or deprecated.** None in the number. Stable/longterm branches are declared end-of-life by the kernel maintainers.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-rc\d+` | `v6.0-rc1`, `6.13-rc3`, `6.1.55-rc1` |
| dev | `next-YYYYMMDD (linux-next)` | `next-20240101` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | .z stable update |
| prerelease | -rcN |

**Conventions with no SemVer equivalent**

- Numbering is not semantic: 5.0 followed 4.20; the first component carries no compatibility meaning.
- OSV Linux 'versions' arrays use tags with a leading v while ECOSYSTEM range events do not.
- OSV GIT ranges carry commit hashes because fixes are backported across stable trees.
- Only the name Kernel is supported in OSV.

**Known gaps**

- Ordering is derived, not from a normative comparator.
- next- tag naming was not retrieved from a document.
- v-prefix mapping between versions arrays and range events is inferred from sample data.

### Nix/nixpkgs (pname-version, compareVersions)

`nix`. Ecosystems: `nix`, `nixpkgs`, `nixos`. purl types: `nix?`.

Sources: <https://nix.dev/manual/nix/stable/language/builtins.html> <https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md> <https://github.com/NixOS/nix/blob/master/src/libstore/names.cc>

**Stable release rule.** UNSTABLE iff the version contains the word unstable (-unstable-YYYY-MM-DD, 0-unstable-..., legacy unstable-...), a delimited pre-release word (alpha|beta|rc|pre|preview|prerelease|milestone|candidate)\d*, a VCS word (git|svn|hg|bzr|cvs followed by digits/hex), or nightly/dev/devel/snapshot/canary. Plain dotted numbers, date versions and -bin style tags are STABLE. Ordering must not be used to detect pre-releases (rc sorts above).

**Pre-release.** Only the literal component 'pre' (0.12pre12876) sorts below the release and below end of string; rc/beta/alpha are ordinary words and sort ABOVE the release.

**Build metadata.** None; '+' stays inside a word component.

**Epoch.** None.

**Post-release.** <last>-unstable-YYYY-MM-DD sorts above <last> and below the next release; extra numeric component sorts above.

**Yanked or deprecated.** Not in the version. meta.knownVulnerabilities / insecure / broken attributes, or removal from nixpkgs (alias throws).

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| git-snapshot | `(^\|-)unstable-YYYY-MM-DD` | `0-unstable-2024-01-01`, `2.2-unstable-2022-03-15` |
| prerelease | `delimited alpha\|beta\|rc\|pre words` | `0.3.1rc2`, `1.0pre1`, `0.12pre12876` |
| nightly | `word nightly` | `1.0-nightly-20240101` |
| dev | `words dev\|devel\|snapshot\|canary` | `1.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | -unstable-YYYY-MM-DD or extra component |
| prerelease | literal 'pre' (only) |

**Conventions with no SemVer equivalent**

- Derivation name pname-version splits at the first '-' not followed by a letter, so a version must start with a digit.
- '.' and '-' are interchangeable component separators; '_' and '+' are not.
- nixpkgs: <last-release>-unstable-YYYY-MM-DD for commits, 0-unstable-YYYY-MM-DD when no release exists.
- Components that parse as int compare numerically; a word is below a number (2.3a < 2.3.1); end of string is below numbers and words (1.0 < 1.0.0, 1.0 < 1.0a).
- Channels (nixos-unstable) are branches and unrelated to -unstable- in versions.

**Known gaps**

- No authoritative definition of 'stable' for Nix versions; markers are nixpkgs conventions plus common upstream words.
- Components overflowing int fall back to string comparison (untested).
- purl type for Nix is unverified.

### RPM (epoch:version-release)

`rpm`. Ecosystems: `red hat`, `rhel`, `redhat`, `centos`, `fedora`, `rocky linux`, `rocky`, `almalinux`, `suse`, `sles`, `opensuse`, `amazon`, `amazon linux`, `oracle`, `oracle linux`, `mageia`, `photon os`, `photon`, `azure linux`, `azurelinux`, `openeuler`, `tuxcare`. purl types: `rpm`.

Sources: <https://github.com/rpm-software-management/rpm/blob/master/docs/man/rpm-version.7.scd> <https://docs.fedoraproject.org/en-US/packaging-guidelines/Versioning/> <https://docs.fedoraproject.org/en-US/packaging-guidelines/DistTag/> <https://github.com/rpm-software-management/rpm/blob/master/rpmio/rpmvercmp.cc>

**Stable release rule.** A version is STABLE unless its version or release contains: a '~' (prerelease); a '^' (snapshot); a delimited pre-release word (alpha|beta|rc|pre|preview|prerelease|milestone|candidate)\d*; a VCS/nightly/dev marker (git|svn|hg|bzr|cvs|darcs followed by digits/hex, \d{8}g[0-9a-f]{7,}, nightly, dev, snapshot); or a release matching ^0(\.|$) (legacy Fedora pre-release/snapshot Release: 0.N.*). Dist tags and z-stream suffixes (.el9, .el9_3, .el9_3.5, .fc40, .module+el8.9.0+..., .amzn2023, .lp155, .mga9, .ph5, 150500.3.12.1) are STABLE rebuilds; a '~' that precedes only a stable backport token (~bpo, ~deb, ~esm, ~NN.NN) is also stable.

**Pre-release.** Tilde: 2.0~rc1 sorts before 2.0 and before end of string; tilde also appears in the release field. Legacy Fedora convention Release: 0.N.rc1 sorts below Release 1.

**Build metadata.** None. Separators (. _ +) are interchangeable and ignored; any alphanumeric text is compared.

**Epoch.** Integer before ':' in EVR, default 0, most significant component.

**Post-release.** Caret: 2.0^20250611 sorts after 2.0 but before 2.0.1 (snapshot after base); or an extra segment (2.0.post1).

**Yanked or deprecated.** No in-band flag. Repositories drop builds; errata supersede with higher release; Obsoletes/Provides tags; epoch bump for backwards moves.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `~ in version or release; delimited alpha\|beta\|rc\|pre words; release ^0\.` | `2.0~rc1-1.fc40`, `1.0.0.rc3-2.fc40`, `1.0-0.1.rc1.fc40` |
| snapshot | `^<date\|number>[.]<scm><rev> in version` | `2.0^20250611git0123abc-1.fc40`, `1.0^1.git0123abc-1.fc40` |
| git-snapshot | `(git\|svn\|hg\|bzr\|cvs) + digits/hex, or <date>g<7+hex>` | `1.0-0.3.20240101git0123abc.fc40`, `1.0-1.git20240101.fc40` |
| nightly | `delimited word nightly` | `1.0.nightly-1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | EPOCH |
| postRelease | ^ operator (snapshot) or extra segment |
| prerelease | ~ operator in VERSION |

**Conventions with no SemVer equivalent**

- RELEASE is the packaging revision, compared only after VERSION is equal; reset to 1 when VERSION changes.
- Dist tags %{?dist}: .el9, .el9_3 (z-stream), .fc40, .module+el8.x, .amzn2023, .lp155, .mga9, .ph5; SUSE release counters like 150500.3.12.1.
- Fedora snapshot field after caret: <date>.<rev>, <date><scm><rev>, <number>.<scm><rev>, scm in git|svn|hg|snap or one letter.
- Version: 0 when upstream never chose a version.
- Underscore as visual separator (1.2~pre1, 1.2_final) has no ordering effect.
- Non-ASCII characters are ignored by rpmvercmp (1.1.a-alpha == 1.1.b-beta equal).
- Dependency comparison skips RELEASE when the constraint has none.

**Known gaps**

- The ^0\. release rule is a convention and can false-positive on distros using release 0 for other purposes.
- rpm releases that introduced ~ and ^ are from memory; RHEL 7 (rpm 4.11) lacks ^.
- Dist-tag shapes for Mageia, Photon, Azure Linux, openEuler are observed, not specified.
- Missing-epoch semantics in dependency constraints were not verified.

### Wolfi/Chainguard apk (go-apk strict subset, melange -rN)

`wolfi`. Ecosystems: `wolfi`, `chainguard`, `docker hardened images`, `cleanstart`. purl types: `apk`.

Sources: <https://github.com/chainguard-dev/melange/blob/main/docs/BUILD-FILE.md> <https://github.com/chainguard-dev/go-apk/blob/main/pkg/apk/version.go>

**Stable release rule.** Version must match the go-apk regex ^[0-9]+(\.[0-9]+)*[a-z]?((_alpha|_beta|_pre|_rc)[0-9]*)?((_cvs|_svn|_git|_hg|_p)[0-9]*)?(-r[0-9]+)?$ (else unparseable). UNSTABLE iff it has _(alpha|beta|pre|rc)\d* or _(git|hg|cvs|svn)\d*. -rN (melange epoch / security rebuild), _p<N> and a trailing letter are STABLE.

**Pre-release.** One optional _alpha|_beta|_pre|_rc suffix (+ number); sorts below the release (none is ranked above rc).

**Build metadata.** None; ~hash is rejected by go-apk.

**Epoch.** None. melange 'epoch' is the apk -rN revision, not an RPM/dpkg epoch.

**Post-release.** One optional _cvs|_svn|_git|_hg|_p suffix (+ number) after the pre suffix; cvs < svn < git < hg < p.

**Yanked or deprecated.** No in-band flag. Rolling repository index; superseded builds are removed; advisories are published as OSV records with fixed X-rN.

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `_(alpha\|beta\|pre\|rc)\d*` | `1.0.0_rc1-r0`, `2.0.0_beta3-r2` |
| git-snapshot | `_(git\|hg\|cvs\|svn)\d*` | `0_git20240101-r0`, `1.0_git20240101-r0` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none (melange epoch == -rN) |
| postRelease | _p<N>, _git<date>, etc. |
| prerelease | _alpha/_beta/_pre/_rc suffix |

**Conventions with no SemVer equivalent**

- package.epoch N in melange renders as <name>-<version>-rN.apk; monotonically increasing from 0.
- Snapshot pkgver <last>_git<YYYYMMDD>, and 0_git<YYYYMMDD> for projects with no release (seen in 2 of 120 sampled Wolfi packages).
- Version streams are separate package names (php-8.1, php-8.2); apk add foo=~4.5.6 is a dependency-expression prefix match, not a version syntax.
- go-apk treats 1.0 == 1.0-r0 and 1.01 == 1.1; C apk-tools does not.

**Known gaps**

- OSV does not state which comparator Wolfi/Chainguard consumers use; C apk-tools semantics differ on 1.0 vs 1.0-r0, leading zeros, ~hash and repeated suffixes.
- Docker Hardened Images and CleanStart are mapped here by assumption.
- Only a 120-package sample of Wolfi definitions was read.

## Tags, channels and schemes that are not cleanly orderable

### Apple OS versions and build numbers (macOS, iOS, bundles)

`apple`. Ecosystems: `apple`, `cocoapods-bundle`, `ios`, `ipados`, `macos`, `swift`. purl types: `generic?`.

Sources: <https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleversion> <https://lowendmac.com/2025/how-to-read-and-interpret-apple-os-build-numbers/>

**Stable release rule.** marketing X.Y[.Z] tuples are comparable within one platform; stable if build number has no trailing lowercase letter and no beta/RC label; never compare across platforms

**Pre-release.** build number ending in a lowercase letter (23D5033f) = developer beta; labels "beta"/"RC" in marketing text

**Build metadata.** build number in parentheses

**Post-release.** Rapid Security Response suffix (a) has no tuple

**Yanked or deprecated.** Apple withdraws/replaces builds; no flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `^\d+[A-Z]\d{3,}[a-z]$` | `23D5033f`, `22C5142f` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | build number |
| epoch | none |
| postRelease | (a) RSR |
| prerelease | lowercase build suffix |

**Conventions with no SemVer equivalent**

- Build number NNLnnnn: train digits, capital letter = minor train, sequence
- Old majors get security updates that are newer by date than the latest major

**Known gaps**

- No first-party doc for the build-number structure was retrievable; relies on community explanations (explicitly informal).
- Cross-platform marketing numbering (iOS vs macOS vs watchOS) is not unified; do not compare across platforms.

### Where "highest number wins" or "newest date wins" gives the WRONG latest (LTS lines, back-port point releases, floating majors, 0.x carets)

`backport-branches`. Ecosystems: `all`, `docker`, `github`, `github-actions`, `java`, `linux`, `nodejs`, `npm`, `openssl`, `pypi`, `python`.

Sources: <https://pypi.org/pypi/{ruff,django,certifi,black,pip,Twisted,homeassistant}/json> <https://semver.org> <https://docs.npmjs.com/cli/v10/commands/npm-dist-tag>

**Stable release rule.** meta-rule: true latest = max stable tuple per the underlying scheme; never newest-by-date; old-line point release = line key lower than the max line key; flags/dist-tags/channels decide stability where the string is plain

**Pre-release.** defer to the underlying scheme

**Build metadata.** defer

**Yanked or deprecated.** defer

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| floating-tag | `caret/tilde on 0.x pins the minor: ^0.15.10 resolves to 0.15.22` | `^0.15.10` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | n/a |
| epoch | n/a |
| postRelease | n/a |
| prerelease | n/a |

**Conventions with no SemVer equivalent**

- META scheme, not a real version format: ordering "none" means defer to the scheme of the package
- Real inversions: Django 190/382, Node 465/875; ruff 1/429 (no 0.15.x vs 0.17.x inversion)

**Known gaps**

- Only PyPI datasets have per-file upload time; GitHub published_at can be bulk-edited (actions/checkout released six majors at once).
- Docker Hub last_updated is mutable.

### Browser extension manifest versions (Chrome, Edge, Firefox)

`browser-extension`. Ecosystems: `browser-extension`, `chrome`, `chrome-extension`, `edge`, `firefox`, `webstore`. purl types: `generic?`.

Sources: <https://developer.chrome.com/docs/extensions/reference/manifest/version> <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/version>

**Stable release rule.** no string rule: a version is stable unless the store channel/listing or version_name says otherwise; validity: 1-4 integers, each 0-65535 (Chrome), no leading zeros, not all zero

**Pre-release.** none in `version`; use `version_name` or a separate listing/channel; legacy Firefox toolkit format allows pre/a/b/rc

**Build metadata.** 4th integer by convention

**Yanked or deprecated.** store delist/block (Chrome Web Store, AMO), browser blocklist by id+version range; no yank flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `legacy Firefox: ^\d+(\.\d+)*(pre\|a\|b\|rc)\d*$; Chrome: version_name text` | `1.0b2`, `1.0pre1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | 4th integer |
| epoch | none |
| postRelease | none |
| prerelease | none |

**Conventions with no SemVer equivalent**

- Fields capped at 65535 on Chrome so YYYYMMDD cannot be one field
- Update manifest picks the highest numeric version
- Each store keeps its own counter

**Known gaps**

- No pre-release representation, so stability must come from the store channel or version_name.
- Overflow of 65535 for CalVer/date fields on Chrome.
- AMO's nine-digit allowance is from MDN prose only.

### CalVer and date-based versions (calver.org)

`calver`. Ecosystems: `calver`, `android`, `docker`, `generic`, `github`, `homeassistant`, `jetbrains`, `npm`, `pypi`, `ubuntu`, `unity`. purl types: `pypi`, `npm`, `generic?`.

Sources: <https://calver.org/> <https://peps.python.org/pep-0440/> <https://semver.org/>

**Stable release rule.** numeric tuple with no pre/dev part; CalVer shape itself is not unstable; parse integers (2024.02.02 -> 2024.2.2), never compare strings; detect CalVer with calver-detection.json

**Pre-release.** PEP 440 aN/bN/rcN/.devN or -rcN modifier on a CalVer base; yt-dlp style YYYY.M.D.HHMMSS.dev0

**Build metadata.** rare +hash

**Epoch.** PEP 440 N! after a scheme switch

**Post-release.** .postN or same-day counter (.1)

**Yanked or deprecated.** registry-specific (PyPI yank etc.)

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-<ident>(.<ident>)*` | `2024.1.0rc1`, `2024.1.0.dev1` |
| nightly | `-nightly.<date> modifier` | `2025.2.0-nightly.20250101` |
| dev | `\.dev\d+$` | `2026.9.27.232945.dev0` |
| prerelease | `(a\|b\|rc)\d+$\|-rc\d+$` | `2024.1.0rc1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | rare |
| epoch | PEP 440 epoch |
| postRelease | micro counter |
| prerelease | modifier |

**Conventions with no SemVer equivalent**

- Calendar segments YYYY, YY, 0Y, M, 0M, W, 0W, D, 0D plus MAJOR/MINOR/MICRO counters.
- Zero-padded months (22.04) are invalid SemVer.
- tzdata style YYYYa..z letter suffix.
- Major is a year, not a breaking-change signal; SemVer ranges (^) are meaningless
- Letter-year tzdata 2024b; ISO date versions (2026-10-01); YYYYMMDD single field
- Zero padding (0M/0D) normalised away by PEP 440, illegal in SemVer

**Known gaps**

- No reference implementation; ordering derived from common practice.
- Shape alone cannot tell black 24.2.0 or pip 24.0 from a SemVer major; see index.md detector.
- Rule B depends on release dates; for registries without dates (Maven Central indexes do, some do not) the YY form is unresolvable.
- Calendar semantics (week numbers 0W, YYYY.WW) were not sampled with real packages.
- 80%/20-version/3-year thresholds were tuned on 22 PyPI/npm/CPython/Node datasets, not a large corpus.

### Chocolatey packages (NuGet versions)

`chocolatey`. Ecosystems: `choco`, `chocolatey`, `nuget-choco`. purl types: `chocolatey?`.

Sources: <https://docs.chocolatey.org/en-us/create/create-packages/> <https://learn.microsoft.com/en-us/nuget/concepts/package-versioning>

**Stable release rule.** no dash pre-release label; up to 4 numeric segments (4th = package fix); ordering NuGet-style, labelled sorts below unlabelled

**Pre-release.** dash suffix (-beta, -rc1, -pre20240101); hidden unless `choco --pre`

**Build metadata.** `+` metadata accepted by recent NuGet, ignored

**Post-release.** 4th numeric segment = package fix (or date)

**Yanked or deprecated.** unlist; community-repo moderation rejection/deprecation (deprecation flag unverified)

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-[0-9A-Za-z.-]+(?:\+.*)?$` | `1.0.0-beta`, `1.2.3-pre20240101` |
| nightly | `-nightly` | `1.2.3-nightly20240101` |
| dev | `-(dev\|ci)` | `1.2.3-ci.457` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | ignored |
| epoch | none |
| postRelease | 4th segment |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- 4th segment for package fixes must be used consistently
- Sibling packages <id>.install, <id>.portable, <id>-nightly

**Known gaps**

- NuGet version reference page not fetched; label comparison rules for legacy NuGet were summarized from general knowledge.
- No explicit channels beyond pre-release flag and sibling package IDs.

### Database majors: PostgreSQL, MySQL, MariaDB

`db-majorminor`. Ecosystems: `generic`, `mariadb`, `mysql`, `postgres`, `postgresql`. purl types: `generic?`.

Sources: <https://www.postgresql.org/support/versioning/> <https://dev.mysql.com/doc/refman/8.4/en/mysql-releases.html> <https://mariadb.org/about/#maintenance-policy>

**Stable release rule.** no attached alpha|beta|rc|devel|dmr token; LTS vs Innovation (MySQL 8.4 vs 9.x) and MariaDB LTS series are NOT in the string, so highest-wins can pick a short-support track

**Pre-release.** PostgreSQL attached alpha/beta/rc/devel (17beta1); MySQL -rc/-dmr

**Build metadata.** distro suffix (-0ubuntu0.22.04.1, -MariaDB)

**Yanked or deprecated.** rare out-of-cycle re-release; no flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `^\d+(\.\d+)?(alpha\|beta\|rc)\d*$` | `17beta1`, `17rc1` |
| dev | `devel$` | `18devel` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | distro suffix |
| epoch | none |
| postRelease | none |
| prerelease | attached word |

**Conventions with no SemVer equivalent**

- PostgreSQL: major = first number from 10, first two numbers before (9.6)
- MySQL LTS/Innovation tracks
- Five-year PG support window

**Known gaps**

- LTS membership for MariaDB is policy text only; not machine-derivable from version.
- No upstream machine-readable stability flag for MySQL series (use endoflife.date).

### Docker / OCI image tags

`docker`. Ecosystems: `docker`, `ecr`, `ghcr`, `oci`, `quay`. purl types: `docker`, `oci`.

Sources: <https://github.com/opencontainers/distribution-spec/blob/main/spec.md> <https://github.com/opencontainers/image-spec/blob/main/annotations.md> <https://docs.renovatebot.com/modules/versioning/docker/> <https://docs.docker.com/reference/cli/docker/image/tag/> <https://hub.docker.com/v2/repositories/library/nginx/tags>

**Stable release rule.** stable only if the tag is a fully specified numeric core (>= the image's most specific segment count, e.g. X.Y.Z) with no pre-release token; compare cores only within an identical flavour suffix (text after first `-`); floating aliases (latest, stable, mainline, lts, X, X.Y, codenames), branch/sha/pr tags and digests are NOT pinned versions

**Pre-release.** attached aN/bN/rcN or -rc/-beta/-alpha/-pre/-dev/-nightly/-canary/-edge/-snapshot token in the tag; no ordering rule

**Build metadata.** `+` is not in the tag alphabet; use `_`/`-` or the org.opencontainers.image.version annotation

**Yanked or deprecated.** no yank in OCI; registries delete tags/manifests; Docker Hub `tag_status` active|inactive; vulnerable images are usually rebuilt under the same tag, so pin by digest

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(?i)(?:^\|[-._])(?:rc\|alpha\|beta\|pre\|preview\|ea\|insiders?\|next)(?:[-._]?\d+)?(?:$\|[-._])\|^\d+(?:\.\d+)*(?:a\|b\|rc)\d+` | `3.16.0a1-slim-trixie`, `v1.2.3-rc1` |
| dev | `(?i)(?:^\|[-._])(?:dev\|test)(?:[-._]?\d+)?(?:$\|[-._])` | `1.2.3-dev` |
| snapshot | `(?i)^(?:sha-)?[0-9a-f]{7,40}$\|^pr-\d+$\|snapshot` | `sha-3f2a9c1`, `pr-1234` |
| nightly | `(?i)nightly` | `nightly`, `nightly-20240101` |
| edge | `(?i)^(?:edge\|unstable)$` | `edge` |
| canary | `(?i)canary` | `canary` |
| branch-ref | `^(?:main\|master\|develop\|trunk)$` | `main` |
| floating-tag | `^(?:latest\|stable\|mainline\|lts\|current)$\|^\d+(?:\.\d+)?(?:-.+)?$ (partial core)` | `latest`, `1.31`, `3.12-slim-bookworm` |
| digest | `^(?:.+@)?sha256:[0-9a-f]{64}$` | `sha256:59a9ae22b893...` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | annotation only |
| epoch | none |
| postRelease | none |
| prerelease | attached letters or hyphen token; unordered |

**Conventions with no SemVer equivalent**

- Flavour suffixes (-alpine3.19, -slim, -bookworm, -perl) partition tags into independent version lines
- Cascading aliases: 1.31.8, 1.31, 1, mainline, latest share one digest
- Docker Hub last_updated is the last push (rebuilds), not the release date: nginx 1.28.0 shows 2025-12-09, later than 1.29.0 (2025-08-13)
- Date tags (20240101, 20240101.1) are CalVer-shaped and carry no stability information
- nginx even minor = stable line, odd minor = mainline; both vendor-supported

**Known gaps**

- No normative version grammar; every image author is free to invent one. Flavour/core split is a heuristic and fails for tags like 2024.1-r2 or alpine-3.19-1.2.3 (version after the flavour).
- last_updated on Docker Hub is the last push, so rebuilds make an old version look newest; the OCI created annotation is optional.
- Anonymous Docker Hub paging stops at 1000 results: observed count: 1381 for nginx, page 11+ returned "pagination offset too large for anonymous requests; sign in to page further". A complete list needs authentication or
- GHCR/Quay/ECR use the same OCI grammar; ECR additionally supports tag immutability as a repository setting (can't be assumed).
- Whether mainline/odd-minor products are "stable" is vendor policy (nginx treats mainline as production-ready).

### Git refs (branches, commit SHAs, git-describe strings)

`git-ref`. Ecosystems: `git`, `github-ref`, `gitlab-ref`, `gitref`, `oss-fuzz`. purl types: `github`, `gitlab?`, `generic?`.

Sources: <https://git-scm.com/docs/git-check-ref-format> <https://git-scm.com/docs/git-describe> <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>

**Stable release rule.** only refs/tags/<SemVer-like tag> without pre-release part; branches, HEAD, PR refs, commit SHAs and git-describe strings are never stable releases (resolve branch vs tag first: a branch may be named like a version)

**Pre-release.** none; tag names with -rc1 by convention

**Build metadata.** git describe suffix -N-gSHA means N commits after the tag (development snapshot)

**Yanked or deprecated.** none; force-push, branch/tag deletion

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| branch-ref | `^(?:refs/(?:heads\|remotes\|pull)/.+\|HEAD\|main\|master\|develop\|trunk\|dev\|next)$` | `main`, `refs/heads/release/1.2`, `refs/heads/v1.2.3` |
| digest | `^[0-9a-f]{7,40}$` | `3f2a9c1` |
| snapshot | `-\d+-g[0-9a-f]{7,}(?:-dirty)?$` | `v1.2.3-5-g3f2a9c1` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | git describe suffix |
| epoch | none |
| postRelease | git describe N-after-tag |
| prerelease | none |

**Conventions with no SemVer equivalent**

- Moving refs used as dependency specifiers (go get @main, uses: o/r@main)
- Order only by commit ancestry or commit date; commit dates can be skewed by rebases/cherry-picks

**Known gaps**

- Branch vs tag ambiguity needs the remote ref listing; a bare string cannot be classified reliably.
- Commit dates can be authored out of order (rebases, cherry-picks, clock skew), so recency-by-date is itself noisy.
- Abbreviated SHAs are ambiguous in large repos.

### GitHub tags, Releases and GitHub Actions refs

`github-release`. Ecosystems: `github`, `github-actions`, `github-release`. purl types: `github`.

Sources: <https://docs.github.com/en/rest/releases/releases> <https://github.com/actions/toolkit/blob/main/docs/action-versioning.md> <https://api.github.com/repos/actions/checkout/tags>

**Stable release rule.** Release `prerelease == false` AND `draft == false` AND tag (prefix-stripped) is SemVer without a pre-release part; order by SemVer of the stripped tag, never by published_at; floating major tags (v4, v1.2) and branch/nightly/latest tags are not pinned versions

**Pre-release.** Release `prerelease: true` flag (authoritative) and/or SemVer pre-release suffix in the tag

**Build metadata.** `+build` accepted in tag names, ignored

**Yanked or deprecated.** no yank; maintainers delete Release/tag, flip `prerelease`, or force-move tags; draft releases are unpublished (exclude)

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `Release.prerelease==true \| (?i)(^\|[-._/])(alpha\|beta\|rc\|pre\|preview)([-._]?\d+)?($\|[-._/])` | `v6-beta`, `v2.0.0-rc.1` |
| nightly | `(?i)^(nightly\|continuous)([-._]?[\d-]+)?$` | `nightly`, `nightly-2024-01-01` |
| snapshot | `^v0\.0\.0-\d{14}-[0-9a-f]{12}$` | `v0.0.0-20240101120000-abcdef123456` |
| branch-ref | `^(?:refs/heads/)?(?:main\|master\|develop)$` | `main` |
| floating-tag | `^v?\d+(?:\.\d+)?$ when full vX.Y.Z tags also exist, or ^latest$` | `v7`, `v4`, `latest` |
| digest | `^[0-9a-f]{40}$` | `3d3c42e5aac5f2f0a7d1b6c9e4f8a0b1c2d3e4f5` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | ignored |
| epoch | none |
| postRelease | none |
| prerelease | Release flag + suffix |

**Conventions with no SemVer equivalent**

- Floating major tags (v1, v4) force-moved to the newest release of the line; back-port releases (v4.4.0 after v7.0.0) are normal
- GitHub /releases/latest sorts by created_at (commit date), not version; actions/checkout published v2.8.0 last on 2026-07-20 while latest is v7.0.1
- Monorepo prefixes (cli-v2.1.0, @scope/pkg@1.2.3); date-named releases (release-2024-01)
- Pin actions by 40-hex commit SHA: immutable, unordered

**Known gaps**

- A repository may tag unrelated things (docs-v2, go/v1) so prefix stripping must be per-repo; false positives are possible.
- created_at (commit date) is stable but can be earlier than the previous release when a back-port branch is cut from old commits; sorting by it can still mis-order close releases.
- Tag API lists tags by ref name, not date; fetch Releases for dates.
- Draft/prerelease flags only exist for Releases, not bare tags. A bare tag v2.0.0-rc.1 is detected by name only.

### Go toolchain versions (go1.27.3, go1.27rc3) and module pseudo-versions

`go-toolchain`. Ecosystems: `go`, `go-toolchain`, `golang`, `gomod`. purl types: `golang`.

Sources: <https://go.dev/doc/toolchain> <https://go.dev/dl/?mode=json&include=all> <https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.27.3.linux-amd64.info> <https://go.dev/ref/mod#versions>

**Stable release rule.** go.dev/dl JSON `stable == true` (excludes rc/beta); order 1.21 < 1.21rc1 < 1.21rc2 < 1.21.0 < 1.21.1 (bare language version lowest); module pseudo-versions are snapshots

**Pre-release.** goX.YrcN / goX.YbetaN attached; go.dev/dl `stable: false`

**Build metadata.** module +incompatible

**Yanked or deprecated.** modules: go.mod `retract`; toolchain: none

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `^go\d+\.\d+(rc\|beta)\d+$` | `go1.27rc3` |
| snapshot | `-\d{14}-[0-9a-f]{12}$` | `v0.0.0-20240101120000-abcdef123456` |
| dev | `^devel \|^gotip$` | `gotip` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | +incompatible |
| epoch | none |
| postRelease | none |
| prerelease | rc/beta attached |

**Conventions with no SemVer equivalent**

- Language version (1.21) != toolchain (go1.21.0)
- Two newest major lines supported; both released simultaneously
- Pseudo-versions for untagged commits

**Known gaps**

- dl JSON has no dates; dates come from the module proxy .info Time for golang.org/toolchain (sampled for 6 versions).
- Pre-1.21 numbering (go1.20 first release) needs special-casing.

### Java / OpenJDK version strings (JEP 223), EA builds, legacy 1.8.0_xxx

`java`. Ecosystems: `java`, `jdk`, `maven-jdk`, `openjdk`, `temurin`. purl types: `generic?`.

Sources: <https://openjdk.org/jeps/223> <https://openjdk.org/jeps/322> <https://api.adoptium.net/>

**Stable release rule.** no -PRE (-ea) and no -SNAPSHOT/-internal; compare VNUM element-wise, then PRE (below none), then BUILD numerically; LTS is vendor policy (-LTS in OPT is informational)

**Pre-release.** -ea (any -PRE per JEP 223) sorts below the same VNUM

**Build metadata.** +BUILD counts in comparison (unlike SemVer); -OPT may not

**Yanked or deprecated.** superseded by quarterly update; no flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-ea(\+\d+)?` | `22-ea+36`, `9-ea+19` |
| snapshot | `-(SNAPSHOT\|internal)` | `17.0.9-SNAPSHOT` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | BUILD counts |
| epoch | none |
| postRelease | update number (legacy _392) |
| prerelease | -ea |

**Conventions with no SemVer equivalent**

- Quarterly update releases for every supported line
- Legacy 1.8.0_392-b08 / 8u392
- LTS every two years (vendor-defined)

**Known gaps**

- JEP 322 text and Adoptium API not fetched; cadence is stated from knowledge.
- The JEP page uses $SECURITY, not $PATCH; $PATCH fourth element is described as free for downstream.

### JetBrains Marketplace plugins and IDE build numbers

`jetbrains`. Ecosystems: `intellij`, `jetbrains`, `jetbrains-plugin`. purl types: `generic?`.

Sources: <https://plugins.jetbrains.com/docs/intellij/plugin-configuration-file.html> <https://plugins.jetbrains.com/docs/marketplace/custom-release-channels.html> <https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html>

**Stable release rule.** plugin update uploaded to the default (empty) Stable channel with no SemVer pre-release part; IDE build numbers (243.12818.47) compare as numeric tuples; EAP/SNAPSHOT builds excluded

**Pre-release.** upload channel other than Stable (eap, beta, alpha, nightly) and/or SemVer pre-release suffix

**Build metadata.** SemVer + (rare)

**Yanked or deprecated.** Marketplace `isHidden` / delist; no consumer-visible yank flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-(eap\|alpha\|beta\|rc)(\.\d+)?$ or channel != Stable` | `1.2.3-eap.4` |
| nightly | `-nightly\|\d{8}$ or nightly channel` | `1.2.3-nightly` |
| snapshot | `(?i)SNAPSHOT` | `243.SNAPSHOT`, `LATEST-EAP-SNAPSHOT` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | SemVer + |
| epoch | none |
| postRelease | none |
| prerelease | channel + suffix |

**Conventions with no SemVer equivalent**

- since-build/until-build compatibility ranges with .* wildcard
- IDE marketing versions are CalVer (2024.1.2) alongside build numbers
- Channels are opt-in custom repositories

**Known gaps**

- Public listing of channel per version needs the Marketplace API (not fetched here).
- Nightly channel naming is user-defined (docs list eap/alpha/beta only).

### Letter-suffix and encoded schemes: zlib, libpng, curl, bash, sqlite

`letter-suffix`. Ecosystems: `bash`, `curl`, `generic`, `github`, `libpng`, `sqlite`, `zlib`. purl types: `generic?`.

Sources: <https://www.sqlite.org/c3ref/c_source_id.html> <https://zlib.net/> <http://www.libpng.org/pub/png/libpng.html> <https://curl.se/docs/releases.html> <https://ftp.gnu.org/gnu/bash/>

**Stable release rule.** parse numeric tuple; stable if no pre-release word; sqlite integer X*1000000+Y*1000+Z maps 1:1 to X.Y.Z

**Pre-release.** libpng attached beta/rc (1.6.44beta01); bash -alpha/-beta/-rc; curl rc- tag prefix; zlib .f dev snapshot

**Build metadata.** bash (1) build counter; zlib -motley

**Post-release.** openssl-style letters (not in this group); bash patchlevel is part of the tuple

**Yanked or deprecated.** none

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(alpha\|beta\|rc)\d*` | `1.6.44beta01`, `5.3-rc1` |
| dev | `\.f$\|-motley` | `1.2.11.f` |
| snapshot | `sqlite-snapshot-YYYYMMDDHHMM` | `sqlite-snapshot-202401151200` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | suffix |
| epoch | none |
| postRelease | per project |
| prerelease | attached/hyphen word |

**Conventions with no SemVer equivalent**

- Integer encoding of dotted versions (sqlite 3045000)
- Underscore tags (curl-8_23_0)
- Patchlevel counters outside the release number (bash)

**Known gaps**

- No single machine-readable spec for zlib/libpng/bash numbering; rules inferred from release pages and file names (only the sqlite integer rule was verified from the spec page).
- Distro-patched versions (e.g. bash 5.1-6ubuntu1) are separate.

### Linux kernel (mainline, stable, longterm, -rc, linux-next)

`linux-kernel`. Ecosystems: `kernel`, `linux`, `linux-kernel`. purl types: `generic?`.

Sources: <https://docs.kernel.org/process/2.Process.html> <https://www.kernel.org/releases.json> <https://www.kernel.org/category/releases.html>

**Stable release rule.** no -rc/next-/-dirty suffix; mainline X.Y, stable X.Y.Z, longterm X.Y.Z; tree (mainline|stable|longterm) is not in the string (releases.json moniker); pre-2.6 odd minors are development

**Pre-release.** -rcN sorts before X.Y; next-YYYYMMDD is linux-next snapshot

**Build metadata.** distro/ABI suffix (-45-generic), -rtN

**Yanked or deprecated.** superseded by next .Z; releases.json `iseol`

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-rc\d+$` | `7.4-rc1` |
| nightly | `^next-\d{8}$` | `next-20261022` |
| snapshot | `-dirty$` | `6.12.114-dirty` |
| odd-minor-unstable | `^2\.(3\|5)\.\d+$ (pre-2.6 only)` | `2.5.75` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | distro suffix |
| epoch | none |
| postRelease | none |
| prerelease | -rcN |

**Conventions with no SemVer equivalent**

- Three parallel trees; longterm point releases often newer by date than mainline
- Distro kernels (5.14.0-427.el9) are a different axis from upstream

**Known gaps**

- Which branch is longterm is only in kernel.org metadata, not in the version string.
- Distro versions need distro-specific comparison (RPM/dpkg).

### Node.js runtime (even/odd lines, LTS codenames, nightly/rc/v8-canary/test dists)

`nodejs`. Ecosystems: `node`, `nodejs`, `runtime-node`. purl types: `generic?`.

Sources: <https://github.com/nodejs/Release/blob/main/README.md> <https://nodejs.org/dist/index.json> <https://nodejs.org/download/{nightly,rc,v8-canary,test}/index.json>

**Stable release rule.** from nodejs.org/dist/index.json only (the release dist); max SemVer for latest; recommended = max among entries with `lts != false`; rc/nightly/v8-canary/test come from other dist dirs

**Pre-release.** -rc.N; separate dist directories: nightly (-nightlyYYYYMMDD<sha>), v8-canary, test

**Build metadata.** none

**Yanked or deprecated.** superseded; `security: true` marks security releases

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-rc\.\d+$` | `v26.4.0-rc.0` |
| nightly | `-nightly\d{8}[0-9a-f]+$` | `v27.0.0-nightly20261022fd20448111` |
| canary | `-v8-canary\d+[0-9a-f]+$` | `v27.0.0-v8-canary2026102205fece4d56` |
| dev | `-test\d+[0-9a-f]+$` | `v27.0.0-test202610201b5fc1479a85aa6174c67e239fad81da92a25b0a` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- LTS is a per-line codename (lts field) not in the string
- Even/odd rule until Node 26; from 27 annual October branch, Alpha phase, every line LTS
- LTS point releases routinely newer by date than newest Current (465/875 inversions)

**Known gaps**

- LTS promotion occurs in October; a snapshot taken before that shows the new line as Current.
- lts can only be read from index.json (or endoflife.date), not from the string.

### npm dist-tags as a channel signal (SemVer versions with unstable channels)

`npm-dist-tag`. Ecosystems: `npm`, `pnpm`, `yarn`. purl types: `npm`.

Sources: <https://docs.npmjs.com/cli/v10/commands/npm-dist-tag> <https://semver.org> <https://registry.npmjs.org/react>

**Stable release rule.** no SemVer pre-release part AND not only reachable via a non-latest unstable dist-tag; "recommended latest" = the `latest` dist-tag; never pick by publish time; 0.0.0-experimental-<sha>-<date> sorts lowest yet is newest

**Pre-release.** SemVer pre-release part plus dist-tag membership (canary, next, experimental, nightly, beta, rc, alpha, insiders, dev)

**Build metadata.** ignored (SemVer)

**Yanked or deprecated.** `npm deprecate` sets `deprecated` on the packument version; `npm unpublish` within limits; no yank

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| canary | `-(canary\|experimental)` | `19.3.0-canary-9ffcb463-20261021`, `0.0.0-experimental-9ffcb463-20261021` |
| dev | `-dev\.\d+` | `7.1.0-dev.20261022.1` |
| nightly | `-(nightly\|insiders)` | `4.6.2-insiders.20220225` |
| prerelease | `-(alpha\|beta\|rc\|preview)` | `19.0.0-rc.1`, `16.3.0-preview.10` |
| floating-tag | `dist-tag names (latest, next, canary, backport)` | `latest` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | identical |
| epoch | none |
| postRelease | none |
| prerelease | identical |

**Conventions with no SemVer equivalent**

- Per-line dist-tags (backport, next-14, v3-latest): `backport` = last published back-port, not the best old-line version
- Date/sha prerelease identifiers: 19.3.0-canary-<sha8>-<yyyymmdd>

**Known gaps**

- Dist-tags are mutable; a snapshot is needed to classify.
- The packument time map has a modified/created pair and per-version times; unpublished versions drop out.
- A publisher may tag latest on an old line (rare).

### OpenSSL (letter-suffix patch releases <= 1.1.1; SemVer-style from 3.0)

`openssl`. Ecosystems: `generic`, `github`, `openssl`. purl types: `generic?`.

Sources: <https://openssl-library.org/policies/releasestrat> <https://api.github.com/repos/openssl/openssl/releases>

**Stable release rule.** no -alpha/-beta/-dev; for <= 1.1.1 trailing letters are post-release (stable); true latest = max tuple, not newest by date (multiple lines release same day)

**Pre-release.** -alphaN/-betaN (3.0+ and pre-1.1.0 -betaN/-preN); GitHub `prerelease: true`

**Build metadata.** distro suffix (1.1.1k-fips)

**Post-release.** trailing letters for <= 1.1.1 (1.1.1w > 1.1.1), compare (length, lexical): z < za

**Yanked or deprecated.** none; fixed in next patch; EOL on policy page

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-(alpha\|beta\|pre)\d+$` | `4.1.0-beta2`, `1.0.2-beta3` |
| dev | `-dev$` | `3.6.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | distro suffix |
| epoch | none |
| postRelease | letter suffix <= 1.1.1 |
| prerelease | identical from 3.0 |

**Conventions with no SemVer equivalent**

- LTS lines (1.1.1, 3.0, 3.5) shipped concurrently with non-LTS lines
- Tags OpenSSL_1_1_1w and openssl-3.5.9

**Known gaps**

- Policy page is a point-in-time document; dates for non-LTS support windows change.
- Letter-suffix collision with generic parsers: 1.1.1w misparsed as prerelease by naive PEP 440/semver libs.

### PHP (and the version_compare special-form ordering)

`php`. Ecosystems: `composer`, `packagist`, `php`. purl types: `composer`, `generic?`.

Sources: <https://www.php.net/manual/en/function.version-compare.php> <https://www.php.net/supported-versions.php>

**Stable release rule.** no dev/alpha/beta/RC token; order per version_compare: unknown < dev < alpha=a < beta=b < RC=rc < # < pl=p after canonicalising (_ - + -> ., dots between digit/non-digit)

**Pre-release.** attached alphaN/betaN/RCN (no hyphen); -dev

**Build metadata.** distro suffix

**Post-release.** `pl`/`p` ranks above the bare release

**Yanked or deprecated.** none; Composer `abandoned` is package-level

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(alpha\|beta\|RC\|rc)\d*$` | `8.4.0RC1`, `8.4.0beta2` |
| dev | `(-dev\|^dev-)` | `8.5.0-dev`, `dev-main` |
| branch-ref | `^dev-.+\|\.x-dev$` | `dev-main`, `8.x-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | distro suffix |
| epoch | none |
| postRelease | pl |
| prerelease | attached word |

**Conventions with no SemVer equivalent**

- Branch support table: 2 years active + 2 years security-only
- Composer stability flags (@dev, @alpha, @beta, @RC, stable)

**Known gaps**

- version_compare rules apply to PHP semantics; other tools (Composer) have parser differences.
- Docker php:8.4-fpm-alpine tags follow the docker scheme.

### CPython interpreter releases (not PyPI packages)

`python-runtime`. Ecosystems: `cpython`, `pyenv`, `python`, `python-runtime`. purl types: `generic?`.

Sources: <https://peps.python.org/pep-0440/> <https://peps.python.org/pep-0602/> <https://endoflife.date/api/python.json> <https://www.python.org/api/v2/downloads/release/>

**Stable release rule.** python.org API `pre_release == false` (no aN/bN/rcN/.devN); true latest = max tuple, ignore date (a newer alpha can post-date a final; old-line security releases are newer than newer minors)

**Pre-release.** aN/bN/rcN attached; python.org API `pre_release: true`; .devN

**Build metadata.** local `+` label (3.13.0+ = modified checkout)

**Epoch.** PEP 440 N! (not used by CPython)

**Post-release.** .postN

**Yanked or deprecated.** not applicable to interpreter downloads

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(a\|b\|rc)\d+$` | `3.16.0a1`, `3.15.0rc3` |
| dev | `\.dev\d+$\|-dev$` | `3.17.0.dev1`, `3.14-dev` |
| snapshot | `\+$` | `3.13.0+` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | local label |
| epoch | N! |
| postRelease | .postN |
| prerelease | aN/bN/rcN |

**Conventions with no SemVer equivalent**

- Annual October cadence; 5-year support per minor (2 bugfix + 3 security)
- PyPy uses its own 7.3.x with pypy3.10-7.3.17 identifiers

**Known gaps**

- PEP 602 and the python.org API behavior beyond the data observed were not re-fetched.
- The is_latest flag on python.org may lag.

### Rust toolchain channels (stable / beta / nightly / dated nightly)

`rust-toolchain`. Ecosystems: `rust`, `rust-toolchain`, `rustc`, `rustup`. purl types: `generic?`.

Sources: <https://rust-lang.github.io/rustup/concepts/channels.html> <https://static.rust-lang.org/dist/channel-rust-stable.toml>

**Stable release rule.** channel `stable` manifest only; beta/nightly and nightly-YYYY-MM-DD are unstable; nightlies share one version string so only the date orders them

**Pre-release.** beta channel 1.N.0-beta.K; nightly 1.N.0-nightly

**Build metadata.** (hash date) in --version

**Yanked or deprecated.** none for toolchains; crates.io has yank (other scheme)

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-beta\.\d+` | `1.100.0-beta.7` |
| nightly | `^nightly(-\d{4}-\d{2}-\d{2})?$\|-nightly` | `nightly-2026-10-22`, `1.101.0-nightly` |
| floating-tag | `^(stable\|beta\|nightly)(-[a-z0-9_-]+)?$` | `stable` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | commit hash date |
| epoch | none |
| postRelease | none |
| prerelease | beta/nightly channels |

**Conventions with no SemVer equivalent**

- Channel names and dated toolchains; rust-toolchain.toml
- Six-week trains, no back-port lines

**Known gaps**

- Nightly rustc strings share a version; hash+date needed.
- MSRV (minimum supported Rust version) fields in crates are separate.

### Scoop manifests

`scoop`. Ecosystems: `scoop`.

Sources: <https://github.com/ScoopInstaller/Scoop/blob/master/lib/versions.ps1> <https://github.com/ScoopInstaller/Scoop/wiki/App-Manifests>

**Stable release rule.** no flag; unstable if a part matches alpha|beta|rc|pre or the version is `nightly`/`nightly-YYYYMMDD`; unstable builds usually live in separate apps/buckets (nightly bucket, firefox-nightly)

**Pre-release.** words alpha|beta|rc|pre in a part sort lower than the bare number

**Build metadata.** `+x` is rewritten to `-x` and treated as POST-release (greater than base)

**Post-release.** `+N` suffix

**Yanked or deprecated.** bucket maintainers delete/edit manifest; no flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(alpha\|beta\|rc\|pre)` | `1.2.3-beta.2` |
| nightly | `^nightly(-\d{8})?$` | `nightly`, `nightly-20240115` |
| dev | `(?i)dev` | `1.2.3-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | `+` = post-release (opposite of SemVer) |
| epoch | none |
| postRelease | `+N` |
| prerelease | alpha\|beta\|rc\|pre sort lower |

**Conventions with no SemVer equivalent**

- `nightly` versions compare equal unless UPDATE_NIGHTLY is set, then by trailing yyyyMMdd
- Versioned app aliases (python27, openjdk17) in versions bucket

**Known gaps**

- Behaviour taken from source at fetch time; the + post-release rule was introduced via Scoop PR #3721 per code comment.
- No machine-readable stability field in manifests.

### Ubuntu releases (YY.MM CalVer with .N point releases and LTS)

`ubuntu`. Ecosystems: `docker-ubuntu`, `ubuntu`, `ubuntu-release`. purl types: `generic?`.

Sources: <https://wiki.ubuntu.com/Releases> <https://calver.org/> <https://ubuntu.com/about/release-cycle>

**Stable release rule.** YY.MM[.N] without beta/daily/devel; LTS iff YY even and MM == 04; interim releases have ~9 months support; codenames/rolling/devel are floating aliases

**Pre-release.** -beta/-daily/devel in image or tag names

**Build metadata.** image date suffix (24.04-20241001)

**Post-release.** .N point release (22.04.5)

**Yanked or deprecated.** EOL dates; no yank

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `-(beta\|alpha)$` | `24.04-beta` |
| nightly | `-daily$` | `26.04-daily` |
| floating-tag | `^(devel\|rolling\|latest\|[a-z]+)$ (codenames)` | `noble`, `rolling` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | image date |
| epoch | none |
| postRelease | .N point release |
| prerelease | beta/daily |

**Conventions with no SemVer equivalent**

- LTS derivable from the string (even YY + .04)
- Point releases are respins of the same series

**Known gaps**

- Support-length facts beyond the wiki quotes are from the release-cycle page, not fetched in this run.

### Unity editor versions (2022.3.10f1, 6000.0.23f1)

`unity`. Ecosystems: `unity`, `unity3d`, `upm-editor`. purl types: `generic?`.

Sources: <https://docs.renovatebot.com/modules/versioning/unity3d/> <https://discussions.unity.com/t/what-does-the-f-in-unity-5-1-2f1-mean/593192>

**Stable release rule.** stream letter f (final) or p (patch); a/b unstable; LTS = last cycle of a year, not in the string (highest year.minor may be a Tech stream)

**Pre-release.** stream letters a (alpha) and b (beta)

**Build metadata.** trailing hash (316c1fd686f6) and China suffix c1 ignored

**Post-release.** p (patch) after f

**Yanked or deprecated.** Unity Hub withdrawal; no flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `^\d+\.\d+\.\d+[ab]\d+` | `2023.3.0a17`, `2023.3.0b4` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | hash/c1 |
| epoch | none |
| postRelease | p |
| prerelease | letters a/b |

**Conventions with no SemVer equivalent**

- Year-based major (Unity 6 is 6000.0)
- Letter+counter stream suffix a<b<f<p

**Known gaps**

- No first-party documentation retrievable; relies on Renovate's docs and community statements.
- c1 China suffix and p semantics are from memory/community.

### VS Code Marketplace and Open VSX extensions

`vscode`. Ecosystems: `openvsx`, `vsce`, `vscode`, `vscode-marketplace`. purl types: `vscode-extension?`.

Sources: <https://code.visualstudio.com/api/working-with-extensions/publishing-extension#prerelease-extensions> <https://open-vsx.org/api/ms-python/python> <https://github.com/eclipse/openvsx/issues>

**Stable release rule.** filter out versions whose PreRelease property/preRelease field is true, then take max(major.minor.patch triple); use odd-minor only as a fallback when no flag is available (99/1005 ms-python.python versions disagree with the flag)

**Pre-release.** separate boolean: Marketplace version property `Microsoft.VisualStudio.Code.PreRelease == "true"`, Open VSX `preRelease: true`; semver pre-release tags are not supported in the string; odd minor is a weak hint

**Build metadata.** not allowed on the Marketplace; some extensions embed a date/build id in PATCH (2026.11.2026102101)

**Yanked or deprecated.** publisher unpublish/delete; Marketplace removal for malware; Open VSX `deprecated` on the extension; no per-version yank flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `version property Microsoft.VisualStudio.Code.PreRelease == "true" \| openvsx preRelease == true` | `2026.11.2026102101`, `2026.2.2026031101` |
| odd-minor-unstable | `^\d+\.\d*[13579]\.\d+$ (heuristic only)` | `0.3.1`, `2026.9.2026100801` |
| dev | `-dev$ (Open VSX accepts semver suffixes)` | `2024.23.0-dev` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | none |
| epoch | none |
| postRelease | none |
| prerelease | flag, not string |

**Conventions with no SemVer equivalent**

- Two parallel channels (release even minor, pre-release odd minor) in one version space; pre-release users get whichever is higher
- Per-targetPlatform artifacts (linux-x64, darwin-arm64, web) share a version string
- preview:true is a badge, not a pre-release

**Known gaps**

- Open VSX historically lacked a --pre-release flag in the ovsx CLI; flags are populated from the VSIX manifest where present (unverified in this research beyond the API field).
- The odd/even convention is a recommendation; many extensions ignore it (measured ~10% mismatch).
- Version triple limits are not documented numerically.

### Windows file versions (a.b.c.d), MSI ProductVersion, OS build numbers, KB ids

`windows-version`. Ecosystems: `kb`, `msi`, `nuget-windows`, `windows`, `windows-update`. purl types: `generic?`.

Sources: <https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource> <https://learn.microsoft.com/en-us/windows/win32/msi/productversion>

**Stable release rule.** numeric 4-tuple (files, OS builds) or 3-tuple (MSI: 255.255.65535) with no VS_FF_PRERELEASE flag and no RC/beta text; KB ids are identifiers not versions (order by release date/supersedence)

**Pre-release.** VS_FF_PRERELEASE flag in VS_FIXEDFILEINFO; "RC2"/"beta" in FileVersion string; Insider channel is metadata

**Build metadata.** 4th word / UBR; MSI ignores the 4th field

**Yanked or deprecated.** Windows Update supersede/expire (KB marked superseded); no version yank

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `VS_FF_PRERELEASE flag or (?i)(rc\|beta\|preview) in FileVersion string` | `5.00.RC2` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | 4th field ignored by MSI |
| epoch | none |
| postRelease | UBR |
| prerelease | flag |

**Conventions with no SemVer equivalent**

- 16-bit fields; MSI major/minor max 255, build max 65535
- Servicing branches (19045, 22631) supported in parallel; newer UBR on the older branch is common
- KB numbers are update ids

**Known gaps**

- Does not cover the MSIX/AppX 4-part version rules or .NET AssemblyVersion/InformationalVersion.
- OS build/UBR scheme taken from common knowledge; not fetched.

### Windows Package Manager (winget) PackageVersion

`winget`. Ecosystems: `windows-package-manager`, `winget`, `winget-pkgs`. purl types: `winget?`.

Sources: <https://github.com/microsoft/winget-pkgs/blob/master/doc/manifest/schema/1.12.0/version.md> <https://learn.microsoft.com/en-us/windows/package-manager/package/manifest> <https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerSharedLib/Versions.cpp>

**Stable release rule.** no formal rule; treat a version as unstable if any dot-part has a text tail matching alpha|beta|rc|pre|preview|dev|nightly|canary|insiders|snapshot; insider builds are usually a separate PackageIdentifier; `Latest`/`Unknown` are placeholders, not versions

**Pre-release.** none; any non-numeric tail in a dot-part sorts BELOW the bare number (1.2.3-beta < 1.2.3)

**Build metadata.** none; `+x` tail also sorts below the bare number (differs from SemVer)

**Yanked or deprecated.** manifest PR removed/reverted in winget-pkgs; no yank flag

| Unstable marker | Syntax | Examples |
| --- | --- | --- |
| prerelease | `(?i)(alpha\|beta\|rc\|pre\|preview\|insiders?)` | `1.2.3-beta`, `5.0.0-preview.2` |
| nightly | `(?i)nightly` | `1.2.3-nightly` |
| floating-tag | `^Latest$` | `Latest` |

| SemVer concept | In this scheme |
| --- | --- |
| buildMetadata | tail sorts lower |
| epoch | none |
| postRelease | none |
| prerelease | tail sorts lower; no concept |

**Conventions with no SemVer equivalent**

- Comparer (winget-cli Versions.cpp): split on ".", Integer + Other per part, trailing zero parts dropped, "Latest" > all, "Unknown" < all, leading non-digits trimmed
- Version should equal Add/Remove Programs DisplayVersion, not the marketing version

**Known gaps**

- Comparer details read from source at fetch time (winget-cli master); behaviour can change between releases.
- Cross-source comparison (store vs winget community) uses the same comparer but versions may be differently formatted.

