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
	// After one pass every boundary is its own token, so re-joining with spaces
	// and splitting again must give the identical sequence, boundaries included.
	corpus := []string{
		"npm i pkg && npm i other",
		"a || b ; c | d",
		"a&&b",
		"'a b'",
		"",
		"a|b||c;d&&e",
		"a;;b",
		"a&&&b",
		"a|||b",
		`pip install "requests==2.31.0" 'flask'`,
		`'' "" ' '`,
		"apt-get update&&apt-get install -y curl;rm -rf /var/lib/apt/lists/*",
		"  leading and trailing  ",
		"\t tabbed\tinput \n",
	}

	for _, s := range corpus {
		first := shellishFields(s)
		second := shellishFields(strings.Join(first, " "))
		if !reflect.DeepEqual(first, second) {
			t.Errorf("shellishFields not idempotent for %q: first=%#v second=%#v", s, first, second)
		}
	}
}
