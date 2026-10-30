// Command gen-schemes-doc renders the versioning-scheme catalogue
// (version/schemes.json) as a markdown page, so the documentation and the engines
// are read from one source and cannot drift.
//
//	go run ./version/cmd/gen-schemes-doc > docs/version-schemes.md
//	go run ./version/cmd/gen-schemes-doc -check docs/version-schemes.md
//
// With -check it exits non-zero when the file differs from what would be written.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/version"
)

func main() {
	check := flag.String("check", "", "compare the output with this file instead of printing it")
	flag.Parse()

	var buf bytes.Buffer
	render(&buf)

	if *check != "" {
		if err := checkDoc(*check, buf.Bytes()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		return
	}
	_, _ = os.Stdout.Write(buf.Bytes())
}

// checkDoc compares path with the rendered bytes and returns an error when the
// file cannot be read or differs, with the stderr wording that the command's
// usage documents.
func checkDoc(path string, want []byte) error {
	have, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(have, want) {
		return fmt.Errorf("%s is out of date: run go run ./version/cmd/gen-schemes-doc > %s", path, path)
	}

	return nil
}

var familyTitle = map[string]string{
	"semver":    "SemVer-shaped registries",
	"qualifier": "Qualifier-based schemes (PEP 440, Maven, RubyGems, conda)",
	"distro":    "Operating system and distribution packages",
	"recency":   "Tags, channels and schemes that are not cleanly orderable",
}

var familyOrder = []string{"semver", "qualifier", "distro", "recency"}

func render(b *bytes.Buffer) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	all := version.Catalogue()

	w("# Version schemes\n\n")
	w("Generated from `version/schemes.json` by `go run ./version/cmd/gen-schemes-doc`. Do not edit by hand.\n\n")
	w("Every package ecosystem orders versions in its own way, and each marks \"not a release\" differently.\n")
	w("Safe Harbour needs both: the order, to find the highest release, and the stability rule, to skip\n")
	w("pre-releases, snapshots and nightly builds. This page records each scheme's rules, the sources they\n")
	w("come from, and where an engine knowingly differs from its reference implementation.\n\n")

	w("## The four outcomes\n\n")
	w("| Outcome | Definition |\n| --- | --- |\n")
	w("| `latest` | The highest stable release (pre-releases skipped). For a package whose versions cannot be ordered by number, the most recent stable release by date. |\n")
	w("| `safest` | The highest stable release with no known vulnerability, exploit or malware report. |\n")
	w("| `stable` | The stable release closest to the version you run, so the upgrade is as small as possible. |\n")
	w("| `rolling` | The safer rolling: every version that is not malware published on the release day (UTC) of the highest version, pre-releases and releases with known vulnerabilities included. Like `latest` it follows version order first and date second: a package whose versions cannot be ordered uses its most recent release day. As a fix strategy, the member closest to the version you run. |\n\n")
	w("Malware is removed before any outcome is chosen. `latest`, `safest` and `stable` are then drawn from the\n")
	w("clean versions only (no known vulnerability, exploit or end of life). `rolling` is the exception: it is the\n")
	w("freshest release day with only malware removed, so it tracks the newest code without ever taking a malicious\n")
	w("upload. `rolling` is a list; where a single string is needed it is joined with a comma, which no concrete\n")
	w("version contains (`version.EncodeRolling`).\n\n")

	w("## How a package is judged\n\n")
	w("1. The ecosystem name selects a scheme (`version.SchemeFor`); an unknown ecosystem uses the `generic` scheme.\n")
	w("2. Each version is classified: is it a version of the scheme at all, and is it stable? The reasons an\n")
	w("   unstable version is skipped are `prerelease`, `dev`, `snapshot`, `nightly`, `milestone`, `build-metadata`,\n")
	w("   `local-version`, `pseudo-version`, `git-snapshot`, `branch-ref`, `floating-tag` and `digest`.\n")
	w("3. The package is **orderable** when at least 80%% of its real versions parse under the scheme, the scheme\n")
	w("   can order versions from the string, and the package has not switched between calendar-year and ordinary\n")
	w("   majors. An orderable package takes its highest stable release as `latest`; any other takes the most\n")
	w("   recent one by release date.\n\n")
	w("A release date decides only what the version string cannot. A point release on an old branch is newer by\n")
	w("date than the true latest and must never win on that account.\n\n")

	w("## Schemes\n\n")
	w("%d schemes. Ordering is `exact` where the engine reproduces the reference implementation on every\n", len(all))
	w("recorded vector, `approximate` where it knowingly differs (see known gaps), and `none` where the string\n")
	w("alone cannot be ordered.\n\n")
	w("| Scheme | Ecosystems | Ordering | Fidelity | Recency only |\n| --- | --- | --- | --- | --- |\n")
	byFamily := map[string][]version.Scheme{}
	for _, s := range all {
		byFamily[s.Family] = append(byFamily[s.Family], s)
	}
	for _, fam := range familyOrder {
		for _, s := range byFamily[fam] {
			w("| [%s](#%s) | %s | `%s` | %s | %v |\n", s.Name, anchor(s.Name), list(s.Ecosystems, 6), s.Ordering, s.OrderingFidelity, s.RecencyOnly)
		}
	}
	w("\n")

	for _, fam := range familyOrder {
		if len(byFamily[fam]) == 0 {
			continue
		}
		w("## %s\n\n", familyTitle[fam])
		for _, s := range byFamily[fam] {
			scheme(b, s)
		}
	}
}

func scheme(b *bytes.Buffer, s version.Scheme) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format, args...) }
	w("### %s\n\n", s.Name)
	w("`%s`. Ecosystems: %s.", s.ID, list(s.Ecosystems, 0))
	if len(s.PurlTypes) > 0 {
		w(" purl types: %s.", list(s.PurlTypes, 0))
	}
	w("\n\n")
	if len(s.Spec) > 0 {
		w("Sources:")
		for _, u := range s.Spec {
			w(" <%s>", u)
		}
		w("\n\n")
	}
	field := func(label, text string) {
		if strings.TrimSpace(text) != "" {
			w("**%s.** %s\n\n", label, strings.TrimSpace(text))
		}
	}
	field("Stable release rule", s.StableRule)
	field("Pre-release", s.Prerelease)
	field("Build metadata", s.BuildMetadata)
	field("Epoch", s.Epoch)
	field("Post-release", s.PostRelease)
	field("Yanked or deprecated", s.YankedDeprecated)

	if len(s.UnstableMarkers) > 0 {
		w("| Unstable marker | Syntax | Examples |\n| --- | --- | --- |\n")
		for _, m := range s.UnstableMarkers {
			w("| %s | `%s` | %s |\n", m.Kind, escape(m.Syntax), codeList(m.Examples))
		}
		w("\n")
	}
	if len(s.SemverEquivalents) > 0 {
		keys := make([]string, 0, len(s.SemverEquivalents))
		for k := range s.SemverEquivalents {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w("| SemVer concept | In this scheme |\n| --- | --- |\n")
		for _, k := range keys {
			w("| %s | %s |\n", k, escape(s.SemverEquivalents[k]))
		}
		w("\n")
	}
	bullets := func(label string, items []string) {
		if len(items) == 0 {
			return
		}
		w("**%s**\n\n", label)
		for _, it := range items {
			w("- %s\n", strings.TrimSpace(it))
		}
		w("\n")
	}
	bullets("Conventions with no SemVer equivalent", s.Conventions)
	bullets("Known gaps", s.KnownGaps)
}

func anchor(name string) string {
	var out []rune
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r == ' ':
			out = append(out, '-')
		}
	}

	return string(out)
}

func list(items []string, max int) string {
	if len(items) == 0 {
		return "none"
	}
	shown := items
	more := ""
	if max > 0 && len(items) > max {
		shown, more = items[:max], fmt.Sprintf(", and %d more", len(items)-max)
	}
	out := make([]string, len(shown))
	for i, it := range shown {
		out[i] = "`" + it + "`"
	}

	return strings.Join(out, ", ") + more
}

func codeList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = "`" + escape(it) + "`"
	}

	return strings.Join(out, ", ")
}

// escape keeps a table cell on one line.
func escape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")

	return strings.ReplaceAll(s, "\n", " ")
}
