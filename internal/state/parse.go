package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/PeterSR/spiffex/schema"
)

// MaxStateSize is the largest state document, encoded as JSON (SPEC
// section 6.1).
const MaxStateSize = 1 << 20

// ParseState parses a state document written in YAML or JSON. A document
// that does not match the state schema is refused with Problems.
func ParseState(data []byte) (*State, error) {
	var st State
	if err := parse(data, schema.StateID, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ParseProvider parses one provider document.
func ParseProvider(data []byte) (*Provider, error) {
	var p Provider
	if err := parse(data, schema.ProviderID, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseOrigin parses one origin, in the form it takes under origins in the
// state document.
func ParseOrigin(data []byte) (*Origin, error) {
	var o Origin
	if err := parse(data, schema.OriginID, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func parse(data []byte, schemaID string, out any) error {
	if len(data) > MaxStateSize {
		return fmt.Errorf("the document is %d bytes, more than the %d allowed", len(data), MaxStateSize)
	}
	tree, err := decodeTree(data)
	if err != nil {
		return err
	}
	return decodeChecked(tree, schemaID, out)
}

// decodeChecked checks a decoded document against its size limit and schema,
// then decodes it into out.
func decodeChecked(tree any, schemaID string, out any) error {
	encoded, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	if len(encoded) > MaxStateSize {
		return fmt.Errorf("the document is %d bytes as JSON, more than the %d allowed", len(encoded), MaxStateSize)
	}
	if problems := validateSchema(schemaID, tree); len(problems) > 0 {
		return problems
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// DecodeTree reads one YAML document, JSON included, with the same rules as
// ParseState, into the values JSON decoding would give. It is for storage
// forms that assemble the state document from several files.
func DecodeTree(data []byte) (any, error) {
	if len(data) > MaxStateSize {
		return nil, fmt.Errorf("the document is %d bytes, more than the %d allowed", len(data), MaxStateSize)
	}
	return decodeTree(data)
}

// decodeTree reads one YAML document, JSON included, into the values JSON
// decoding would give, with numbers as json.Number. Only what JSON can say is
// accepted: no anchors or aliases, which can make a small document expand
// enormously, no non-string keys, no merge keys and no custom tags.
func decodeTree(data []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the document is empty")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("want a single YAML document")
	}
	return convertNode(&doc)
}

func convertNode(n *yaml.Node) (any, error) {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return nil, fmt.Errorf("line %d: YAML anchors and aliases are not supported", n.Line)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("the document is empty")
		}
		return convertNode(n.Content[0])
	case yaml.SequenceNode:
		if n.ShortTag() != "!!seq" {
			return nil, fmt.Errorf("line %d: unsupported YAML tag %s", n.Line, n.ShortTag())
		}
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := convertNode(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		if n.ShortTag() != "!!map" {
			return nil, fmt.Errorf("line %d: unsupported YAML tag %s", n.Line, n.ShortTag())
		}
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.AliasNode || k.Anchor != "" {
				return nil, fmt.Errorf("line %d: YAML anchors and aliases are not supported", k.Line)
			}
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return nil, fmt.Errorf("line %d: keys must be strings", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("line %d: key %q appears twice", k.Line, k.Value)
			}
			v, err := convertNode(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.ScalarNode:
		return convertScalar(n)
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}

func convertScalar(n *yaml.Node) (any, error) {
	switch n.ShortTag() {
	case "!!str", "!!timestamp":
		// Timestamps are YAML 1.1; JSON knows them only as strings.
		return n.Value, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return nil, err
		}
		return b, nil
	case "!!int", "!!float":
		var f float64
		if err := n.Decode(&f); err != nil {
			return nil, fmt.Errorf("line %d: %w", n.Line, err)
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("line %d: %s is not a number JSON can hold", n.Line, n.Value)
		}
		// Only the type matters: no field of the state takes a number.
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64)), nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML tag %s", n.Line, n.ShortTag())
}
