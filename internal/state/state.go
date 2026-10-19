// Package state models the issuer's state (SPEC section 6): origins,
// providers and grants. It parses state documents, expands each origin with
// its provider, validates the result, and explains how a subject token would
// fare against it. Nothing here touches the network.
package state

import (
	"encoding/json"
	"errors"
)

// State is the state document (SPEC section 6.1), as written.
type State struct {
	Origins   map[string]*Origin   `json:"origins,omitempty"`
	Providers map[string]*Provider `json:"providers,omitempty"`
	Grants    map[string]*Grant    `json:"grants,omitempty"`
}

// Origin is one origin as written (SPEC section 4). Its fields add to what
// its provider says; Expand combines the two.
type Origin struct {
	Provider string `json:"provider"`
	// With holds values for the provider's parameters.
	With map[string]Strings `json:"with,omitempty"`
	// Prefix is /<origin name> when empty.
	Prefix string `json:"prefix,omitempty"`
	// Name, when set, replaces the provider's name template. It is a pointer
	// because an empty template is a deliberate choice.
	Name      *string            `json:"name,omitempty"`
	Require   []string           `json:"require,omitempty"`
	Match     map[string]Strings `json:"match,omitempty"`
	Deny      map[string]Strings `json:"deny,omitempty"`
	Audiences *Strings           `json:"audiences,omitempty"`
	// SVIDTypes are the kinds of SVID the origin's identities may obtain,
	// jwt and x509 (SPEC section 4.5). Nil takes the default; an empty
	// list is invalid, which omitzero (unlike omitempty) keeps visible to
	// the schema.
	SVIDTypes []string           `json:"svid_types,omitzero"`
	Members   map[string]*Member `json:"members,omitempty"`
}

// Member is a workload of a keys origin (SPEC section 4.2).
type Member struct {
	// Keys are PEM PUBLIC KEY blocks (JSON strings) or JWKs (JSON objects).
	Keys []json.RawMessage `json:"keys"`
}

// Provider is a provider document (SPEC section 5), before parameters are
// substituted.
type Provider struct {
	Description string             `json:"description,omitempty"`
	Overrides   bool               `json:"overrides,omitempty"`
	Params      map[string]*Param  `json:"params,omitempty"`
	Proof       Proof              `json:"proof"`
	Require     []string           `json:"require,omitempty"`
	Match       map[string]Strings `json:"match,omitempty"`
	Deny        map[string]Strings `json:"deny,omitempty"`
	Name        string             `json:"name,omitempty"`
	Audiences   *Strings           `json:"audiences,omitempty"`
	// SVIDTypes is the default for the origin's svid_types (SPEC section 4.5).
	SVIDTypes []string `json:"svid_types,omitzero"`
}

// ParamType is the type of a provider parameter.
type ParamType string

// The parameter types.
const (
	ParamString ParamType = "string"
	ParamList   ParamType = "list"
)

// Param declares a provider parameter (SPEC section 5.1).
type Param struct {
	Type     ParamType `json:"type"`
	Required bool      `json:"required,omitempty"`
	Default  *Strings  `json:"default,omitempty"`
}

// Proof is exactly one of JWT, Keys and Exec.
type Proof struct {
	JWT  *JWTProof  `json:"jwt,omitempty"`
	Keys *KeysProof `json:"keys,omitempty"`
	Exec *ExecProof `json:"exec,omitempty"`
}

// KeysProof is the keys proof: workloads hold private keys whose public halves
// are the origin's members. It has no settings.
type KeysProof struct{}

// JWTProof is the jwt proof (SPEC section 5.2), as written.
type JWTProof struct {
	Issuer          string          `json:"issuer"`
	Audience        string          `json:"audience,omitempty"`
	JWKS            json.RawMessage `json:"jwks,omitempty"`
	JWKSURI         string          `json:"jwks_uri,omitempty"`
	JWKSFile        string          `json:"jwks_file,omitempty"`
	Discovery       bool            `json:"discovery,omitempty"`
	CAFile          string          `json:"ca_file,omitempty"`
	BearerTokenFile string          `json:"bearer_token_file,omitempty"`
	Shared          bool            `json:"shared"`
	// OwnerClaims is a list, or a single string naming a list parameter.
	OwnerClaims      *Strings `json:"owner_claims,omitempty"`
	MaxTokenLifetime string   `json:"max_token_lifetime,omitempty"`
}

// ExecProof is the exec proof (SPEC section 5.4): a local verifier turns the
// subject token into claims. Every field is literal.
type ExecProof struct {
	// Command is an absolute path followed by fixed arguments.
	Command     []string `json:"command"`
	Timeout     string   `json:"timeout,omitempty"`
	Shared      bool     `json:"shared"`
	OwnerClaims []string `json:"owner_claims,omitempty"`
}

// Grant gives SPIFFE identities permissions on the state (SPEC section 8.2).
type Grant struct {
	Who string   `json:"who"`
	Can []string `json:"can"`
	On  []string `json:"on"`
}

// Strings is a string or a list of strings, kept in the form it was written:
// where a parameter goes, and what it may be replaced with, depends on it.
type Strings struct {
	Values []string
	// List is true when the value was written as a list.
	List bool
}

// One returns a Strings written as a single string.
func One(s string) Strings { return Strings{Values: []string{s}} }

// List returns a Strings written as a list.
func List(values ...string) Strings { return Strings{Values: values, List: true} }

// MarshalJSON implements json.Marshaler.
func (s Strings) MarshalJSON() ([]byte, error) {
	if s.List {
		if s.Values == nil {
			return []byte("[]"), nil
		}
		return json.Marshal(s.Values)
	}
	if len(s.Values) != 1 {
		return nil, errors.New("a single string must hold exactly one value")
	}
	return json.Marshal(s.Values[0])
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Strings) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = One(one)
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return errors.New("want a string or a list of strings")
	}
	*s = List(list...)
	return nil
}
