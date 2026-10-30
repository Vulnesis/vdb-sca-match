package parse

import (
	"reflect"
	"strings"
	"testing"
)

func TestShellishFieldsExamples(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "spaced and-operator",
			in:   "npm i pkg && npm i other",
			want: []string{"npm", "i", "pkg", "&&", "npm", "i", "other"},
		},
		{
			name: "all boundaries",
			in:   "a || b ; c | d",
			want: []string{"a", "||", "b", ";", "c", "|", "d"},
		},
		{
			name: "no spaces around and",
			in:   "a&&b",
			want: []string{"a", "&&", "b"},
		},
		{
			// Quotes are trimmed from token edges, not shell grouping:
			// the space still splits the token in two.
			name: "quoted token",
			in:   "'a b'",
			want: []string{"a", "b"},
		},
		{
			name: "empty",
			in:   "",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellishFields(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("shellishFields(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestShellishFieldsIdempotent(t *testing.T) {
	corpus := []string{
		"npm i pkg && npm i other",
		"a || b ; c | d",
		"a&&b",
		"'a b'",
		"",
	}

	for _, s := range corpus {
		first := shellishFields(s)
		second := shellishFields(strings.Join(first, " "))

		// Boundaries may be re-split when joined, so compare only the
		// non-boundary token sequence.
		if got, want := nonBoundaryTokens(second), nonBoundaryTokens(first); !reflect.DeepEqual(got, want) {
			t.Errorf("shellishFields not idempotent for %q: first=%#v second=%#v (non-boundary first=%#v second=%#v)", s, first, second, want, got)
		}
	}
}

func nonBoundaryTokens(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, tok := range toks {
		if !isShellBoundary(tok) {
			out = append(out, tok)
		}
	}
	return out
}
