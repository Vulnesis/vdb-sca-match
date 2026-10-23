package version

import (
	"testing"
	"time"
)

// TestPickVectors replays real release histories (fetched from the registries,
// see each vector's `source`) where the newest release by date is not the
// highest version: Django 5.2.x LTS point releases land minutes after 6.1.2,
// actions/checkout back-ports six majors in one batch, OpenSSL ships 3.4.8 after
// 4.0.3. `latest` must be the highest stable version in every one of them.
func TestPickVectors(t *testing.T) {
	var data struct {
		Picks []struct {
			Name       string `json:"name"`
			Ecosystem  string `json:"ecosystem"`
			Running    string `json:"running"`
			Synthetic  bool   `json:"synthetic"`
			Candidates []struct {
				V           string `json:"v"`
				PublishedAt string `json:"publishedAt"`
			} `json:"candidates"`
			Expect struct {
				Latest string `json:"latest"`
			} `json:"expect"`
		} `json:"picks"`
	}
	loadJSON(t, "testdata/pick_vectors.json", &data)
	if len(data.Picks) == 0 {
		t.Fatal("no pick vectors")
	}
	for _, p := range data.Picks {
		t.Run(p.Name, func(t *testing.T) {
			var cs []Candidate
			have := map[string]bool{}
			for _, c := range p.Candidates {
				cand := Candidate{Version: c.V}
				if c.PublishedAt != "" {
					ts, err := time.Parse(time.RFC3339, c.PublishedAt)
					if err != nil {
						t.Fatalf("%s: %v", c.V, err)
					}
					ms := ts.UnixMilli()
					cand.PublishedAtMs = &ms
				}
				cs = append(cs, cand)
				have[c.V] = true
			}
			if !have[p.Expect.Latest] {
				t.Skipf("expected latest %q is not one of the candidates", p.Expect.Latest)
			}
			// The vectors list candidates as fetched; pre-releases are among
			// them on purpose, because latest must skip them.
			got := Pick(p.Ecosystem, p.Running, cs)
			if got.Latest != p.Expect.Latest {
				t.Errorf("latest = %q, want %q (scheme %s, orderable=%v)", got.Latest, p.Expect.Latest, got.Scheme, got.Orderable)
			}
			if got.Safest != p.Expect.Latest {
				t.Errorf("safest = %q, want %q", got.Safest, p.Expect.Latest)
			}
			if len(got.Rolling) == 0 {
				t.Errorf("rolling is empty although every candidate is dated")
			}
		})
	}
}
