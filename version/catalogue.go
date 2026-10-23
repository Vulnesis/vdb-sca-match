package version

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"
)

//go:embed schemes.json
var schemesJSON []byte

// Scheme is one entry of the versioning-scheme catalogue (schemes.json): what a
// scheme's versions look like, how they order, and what a stable-release filter
// must skip. The Go engines in this package implement the entries; the
// catalogue is the readable record of why, with the sources.
type Scheme struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Family     string   `json:"family"`
	Spec       []string `json:"spec"`
	Ecosystems []string `json:"ecosystems"`
	PurlTypes  []string `json:"purlTypes"`
	// Ordering names the comparison algorithm; "none" means the string alone
	// cannot be ordered and recency by release date decides.
	Ordering         string `json:"ordering"`
	OrderingFidelity string `json:"orderingFidelity"`
	// RecencyOnly is true, false or "partial".
	RecencyOnly       any               `json:"recencyOnly"`
	Prerelease        string            `json:"prerelease"`
	BuildMetadata     string            `json:"buildMetadata"`
	Epoch             string            `json:"epoch"`
	PostRelease       string            `json:"postRelease"`
	YankedDeprecated  string            `json:"yankedDeprecated"`
	StableRule        string            `json:"stableRule"`
	UnstableMarkers   []UnstableMarker  `json:"unstableMarkers"`
	SemverEquivalents map[string]string `json:"semverEquivalents"`
	Conventions       []string          `json:"conventions"`
	KnownGaps         []string          `json:"knownGaps"`
	VectorSchemes     []string          `json:"vectorSchemes"`
}

// UnstableMarker documents one syntax that makes a version unstable.
type UnstableMarker struct {
	Kind     string   `json:"kind"`
	Syntax   string   `json:"syntax"`
	Examples []string `json:"examples"`
}

var (
	catalogueOnce sync.Once
	catalogue     []Scheme
	catalogueByID map[string]*Scheme
)

func loadCatalogue() {
	catalogueOnce.Do(func() {
		if err := json.Unmarshal(schemesJSON, &catalogue); err != nil {
			panic("version: schemes.json is not valid: " + err.Error())
		}
		catalogueByID = make(map[string]*Scheme, len(catalogue))
		for i := range catalogue {
			catalogueByID[catalogue[i].ID] = &catalogue[i]
		}
	})
}

// Catalogue returns every scheme in the catalogue, ordered by family then id.
func Catalogue() []Scheme {
	loadCatalogue()
	out := make([]Scheme, len(catalogue))
	copy(out, catalogue)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// SchemeByID returns the catalogue entry for a scheme id.
func SchemeByID(id string) (Scheme, bool) {
	loadCatalogue()
	s, ok := catalogueByID[id]
	if !ok {
		return Scheme{}, false
	}
	return *s, true
}

// recencyOnly reports whether the scheme's versions cannot be ordered from the
// string alone (git refs). "partial" schemes are ordered when they parse.
func (s Scheme) recencyOnly() bool {
	b, ok := s.RecencyOnly.(bool)
	return ok && b
}
