package parse

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildPurl builds a Package URL string for a dependency from its name,
// version, and ecosystem. It is the inverse of ParsePurl and must stay
// byte-identical with the CLI's cdx.BuildLocalPurl so that a manifest parsed
// here keys the same vulnerability rows the CLI would request. An ecosystem with
// no alias below is used as the purl type as is (deb, apk, oci, github-actions,
// ...), so every package the parsers emit gets a purl; only an empty ecosystem
// yields "". vdb-api skips a package whose purl is "", so narrowing this drops
// those packages from matching.
func BuildPurl(name, version, ecosystem string) string {
	purlType := ecosystemToPurlType(ecosystem)
	if purlType == "" {
		return ""
	}

	// npm scoped packages: @scope/name → pkg:npm/scope/name
	if purlType == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:npm/%s/%s@%s",
					url.PathEscape(parts[0]), parts[1], url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:npm/%s/%s", url.PathEscape(parts[0]), parts[1])
		}
	}

	// Maven group:artifact → pkg:maven/group/artifact
	if purlType == "maven" && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:maven/%s/%s@%s",
					url.PathEscape(parts[0]), url.PathEscape(parts[1]), url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:maven/%s/%s",
				url.PathEscape(parts[0]), url.PathEscape(parts[1]))
		}
	}

	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, url.PathEscape(name), url.PathEscape(version))
	}
	return fmt.Sprintf("pkg:%s/%s", purlType, url.PathEscape(name))
}

func ecosystemToPurlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "golang", "go":
		return "golang"
	case "cargo", "rust":
		return "cargo"
	case "gem", "rubygems":
		return "gem"
	case "maven", "java":
		return "maven"
	case "composer", "php":
		return "composer"
	case "nuget":
		return "nuget"
	case "pub", "dart":
		return "pub"
	case "hex", "elixir":
		return "hex"
	case "swift":
		return "swift"
	case "helm":
		return "helm"
	case "conda":
		return "conda"
	case "clojars", "clojure":
		// Clojure coordinates are Maven group:artifact pairs.
		return "maven"
	default:
		return ecosystem
	}
}
