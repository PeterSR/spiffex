package state

import (
	"sort"
	"strings"
)

// paramRef returns the parameter a value refers to, when the value is
// exactly $<name>. A $ anywhere else is literal text (SPEC section 5.1).
func paramRef(s string) (string, bool) {
	name, ok := strings.CutPrefix(s, "$")
	if !ok || !paramNameRE.MatchString(name) {
		return "", false
	}
	return name, true
}

// paramPositions lists where a provider may use parameters, for messages.
const paramPositions = "only issuer, audience, jwks_uri and owner_claims of a jwt proof, audiences, and the patterns of match and deny take parameters"

// checkRefs checks that every parameter a provider uses is declared, has a
// type that fits where it is used, and is used only where parameters are
// allowed.
func (v *validator) checkRefs(path string, p *Provider) {
	declared := func(at, name string) *Param {
		decl := p.Params[name]
		if decl == nil {
			v.add(at, "parameter %s is not declared in params", name)
		}
		return decl
	}
	str := func(at, s string) {
		if name, ok := paramRef(s); ok {
			if decl := declared(at, name); decl != nil && decl.Type != ParamString {
				v.add(at, "parameter %s is a list, but a single string goes here", name)
			}
		}
	}
	// list checks a string-or-list field. A list parameter can only stand
	// for the whole value, and only where a list is expected.
	list := func(at string, s *Strings, listOnly bool) {
		if s == nil {
			return
		}
		if s.List {
			for i, elem := range s.Values {
				str(index(at, i), elem)
			}
			return
		}
		name, ok := paramRef(s.Values[0])
		if !ok {
			if listOnly {
				v.add(at, "want a list, or a parameter of type list")
			}
			return
		}
		if decl := declared(at, name); decl != nil && listOnly && decl.Type != ParamList {
			v.add(at, "parameter %s is a string, but a list goes here", name)
		}
	}
	literal := func(at, s string) {
		if name, ok := paramRef(s); ok {
			v.add(at, "$%s is taken literally here: %s", name, paramPositions)
		}
	}

	literal(field(path, "name"), p.Name)
	for i, r := range p.Require {
		literal(index(field(path, "require"), i), r)
	}
	for _, kind := range []string{"match", "deny"} {
		conds := p.Match
		if kind == "deny" {
			conds = p.Deny
		}
		for _, claim := range sortedKeys(conds) {
			at := field(field(path, kind), claim)
			literal(at, claim)
			patterns := conds[claim]
			list(at, &patterns, false)
		}
	}
	list(field(path, "audiences"), p.Audiences, false)
	if j := p.Proof.JWT; j != nil {
		jp := field(field(path, "proof"), "jwt")
		str(field(jp, "issuer"), j.Issuer)
		str(field(jp, "audience"), j.Audience)
		str(field(jp, "jwks_uri"), j.JWKSURI)
		list(field(jp, "owner_claims"), j.OwnerClaims, true)
		literal(field(jp, "jwks_file"), j.JWKSFile)
		literal(field(jp, "ca_file"), j.CAFile)
		literal(field(jp, "bearer_token_file"), j.BearerTokenFile)
		literal(field(jp, "max_token_lifetime"), j.MaxTokenLifetime)
	}
	if e := p.Proof.Exec; e != nil {
		ep := field(field(path, "proof"), "exec")
		for i, arg := range e.Command {
			literal(index(field(ep, "command"), i), arg)
		}
		literal(field(ep, "timeout"), e.Timeout)
		for i, claim := range e.OwnerClaims {
			literal(index(field(ep, "owner_claims"), i), claim)
		}
	}
}

// checkParams checks a provider's parameter declarations.
func (v *validator) checkParams(path string, p *Provider) {
	for _, name := range sortedKeys(p.Params) {
		at := field(field(path, "params"), name)
		decl := p.Params[name]
		if !paramNameRE.MatchString(name) {
			v.add(at, "parameter names are 1 to 63 characters from a-z, 0-9, _ and -, starting with a letter")
		}
		switch decl.Type {
		case ParamString, ParamList:
		default:
			v.add(field(at, "type"), "want string or list, not %q", decl.Type)
			continue
		}
		if decl.Required == (decl.Default != nil) {
			v.add(at, "set either required: true or a default")
			continue
		}
		if decl.Default != nil && decl.Default.List != (decl.Type == ParamList) {
			v.add(field(at, "default"), "want a %s, like the parameter's type", decl.Type)
		}
	}
}

// substituter replaces parameter references with an origin's values, in one
// pass: what it puts in place is never looked at again. Each value it puts in
// is checked with the rules of the field it lands in; failures are reported
// against the parameter, since that is where the operator has to fix them.
type substituter struct {
	values map[string]Strings
	report func(param string, err error)
}

// string substitutes a single-string field and returns the parameter used,
// if any.
func (s substituter) string(v string, check func(string) error) (string, string) {
	name, ok := paramRef(v)
	if !ok {
		return v, ""
	}
	val := s.values[name]
	if val.List || len(val.Values) != 1 {
		return "", name
	}
	out := val.Values[0]
	if check != nil {
		if err := check(out); err != nil {
			s.report(name, err)
		}
	}
	return out, name
}

// list substitutes a string-or-list field and returns the resulting list.
func (s substituter) list(v *Strings, check func(string) error) []string {
	if v == nil {
		return nil
	}
	if !v.List {
		name, ok := paramRef(v.Values[0])
		if !ok {
			return []string{v.Values[0]}
		}
		values := s.values[name].Values
		if check != nil {
			for _, elem := range values {
				if err := check(elem); err != nil {
					s.report(name, err)
				}
			}
		}
		return append([]string(nil), values...)
	}
	out := make([]string, len(v.Values))
	for i, elem := range v.Values {
		out[i], _ = s.string(elem, check)
	}
	return out
}

func (s substituter) conditions(conds map[string]Strings) []Condition {
	var out []Condition
	for _, claim := range sortedKeys(conds) {
		patterns := conds[claim]
		out = append(out, Condition{Claim: claim, Patterns: toPatterns(s.list(&patterns, checkPattern))})
	}
	return out
}

// literalConditions converts an origin's own match or deny entries, which
// take no parameters.
func literalConditions(conds map[string]Strings) []Condition {
	var out []Condition
	for _, claim := range sortedKeys(conds) {
		out = append(out, Condition{Claim: claim, Patterns: toPatterns(conds[claim].Values)})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
