package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Parse decodes a SARIF document. It is deliberately lenient about unknown
// members (SARIF is extensible by design) but strict about the document being
// a JSON object — a truncated or banner-polluted file must fail here, loudly,
// rather than decode to an empty Log and look like a clean scan.
func Parse(b []byte) (*Log, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	var l Log
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}
	return &l, nil
}

// ParseReader is Parse over an io.Reader.
func ParseReader(r io.Reader) (*Log, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Marshal serialises a Log with the indentation used for on-disk artefacts.
func Marshal(l *Log) ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// ToMap round-trips a Log through JSON into the generic map shape the API
// envelope carries. Callers that already hold the raw bytes should unmarshal
// those instead — this exists for the build-then-send path.
func ToMap(l *Log) (map[string]any, error) {
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
