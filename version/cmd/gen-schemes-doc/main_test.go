package main

import (
	"bytes"
	"os"
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
