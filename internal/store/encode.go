package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/PeterSR/spiffex/internal/state"
)

// maxStoredSize bounds what is read from storage. The document may be at
// most state.MaxStateSize as JSON; YAML with comments can be somewhat
// larger.
const maxStoredSize = 4 * state.MaxStateSize

// canonical encodes a state as JSON and parses it again, so that what is
// written has the shapes and order a parsed state has, and so that a state
// built in Go is checked against the schema before it is stored.
func canonical(st *state.State) (*state.State, error) {
	data, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return state.ParseState(data)
}

// toTree converts anything that encodes as JSON into plain maps, lists and
// scalars, with JSON's field names and omissions.
func toTree(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return numbers(tree), nil
}

// numbers replaces json.Number, which YAML would write as a string, with an
// integer or a float.
func numbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = numbers(e)
		}
	case []any:
		for i, e := range t {
			t[i] = numbers(e)
		}
	case json.Number:
		if i, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return i
		}
		f, _ := strconv.ParseFloat(t.String(), 64)
		return f
	}
	return v
}

// encodeYAML writes v as a YAML document, with keys in sorted order.
func encodeYAML(v any) ([]byte, error) {
	tree, err := toTree(v)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(tree); err != nil {
		return nil, fmt.Errorf("encoding YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// encodeJSON writes v as indented JSON.
func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func contentVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Encode writes a state document in the canonical form the stores write:
// YAML, or indented JSON when asJSON is set.
func Encode(st *state.State, asJSON bool) ([]byte, error) {
	st, err := canonical(st)
	if err != nil {
		return nil, err
	}
	if asJSON {
		return encodeJSON(st)
	}
	return encodeYAML(st)
}
