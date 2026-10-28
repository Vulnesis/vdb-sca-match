package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/version-schemes.md is generated from version/schemes.json. A catalogue edit
// that forgets to regenerate it fails here.
func TestDocIsCurrent(t *testing.T) {
	have, err := os.ReadFile("../../../docs/version-schemes.md")
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	render(&want)
	if !bytes.Equal(have, want.Bytes()) {
		t.Fatal("docs/version-schemes.md is out of date: run go run ./version/cmd/gen-schemes-doc > docs/version-schemes.md")
	}
}

func TestCheckDoc(t *testing.T) {
	var want bytes.Buffer
	render(&want)

	t.Run("matching file yields no error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "schemes.md")
		if err := os.WriteFile(path, want.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkDoc(path, want.Bytes()); err != nil {
			t.Fatalf("checkDoc returned an error for a matching file: %v", err)
		}
	})

	t.Run("one byte changed yields out of date error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "schemes.md")
		stale := append([]byte(nil), want.Bytes()...)
		if stale[0] == '#' {
			stale[0] = 'x'
		} else {
			stale[0] = '#'
		}
		if err := os.WriteFile(path, stale, 0o644); err != nil {
			t.Fatal(err)
		}
		err := checkDoc(path, want.Bytes())
		if err == nil {
			t.Fatal("checkDoc returned nil for a stale file")
		}
		wantErr := path + " is out of date: run go run ./version/cmd/gen-schemes-doc > " + path
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("error %q does not contain %q", err, wantErr)
		}
	})

	t.Run("nonexistent path yields an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.md")
		if err := checkDoc(path, want.Bytes()); err == nil {
			t.Fatal("checkDoc returned nil for a nonexistent path")
		}
	})
}
