package state

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseStateYAMLAndJSON(t *testing.T) {
	yamlDoc := `
origins:
  kube: { provider: kubernetes, with: { namespaces: [a, b] }, name: "" }
`
	jsonDoc := `{"origins": {"kube": {"provider": "kubernetes", "with": {"namespaces": ["a", "b"]}, "name": ""}}}`
	for _, doc := range []string{yamlDoc, jsonDoc} {
		st, err := ParseState([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		o := st.Origins["kube"]
		if o.Name == nil || *o.Name != "" || !o.With["namespaces"].List {
			t.Errorf("origin = %+v", o)
		}
		// The document converts to JSON and back without loss.
		data, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseState(data)
		if err != nil {
			t.Fatal(err)
		}
		if again.Origins["kube"].Name == nil {
			t.Error("an explicitly empty name was lost")
		}
	}
}

func TestParseStateRefuses(t *testing.T) {
	tests := []struct {
		name, doc, path, msg string
	}{
		{"unknown top-level field", "clients: {}", "", "additional properties 'clients' not allowed"},
		{"unknown origin field", "origins: { a: { provider: keys, spiffe_id: x } }", "origins.a", "additional properties 'spiffe_id' not allowed"},
		{"missing provider", "origins: { a: { prefix: /a } }", "origins.a", "missing property 'provider'"},
		{"bad origin name", "origins: { A: { provider: keys } }", "origins", "'A' does not match pattern"},
		{"number for a string", "origins: { a: { provider: github, with: { owner_id: 4711 } } }", "origins.a.with.owner_id", "want string"},
		{"two proofs", "providers: { p: { proof: { keys: {}, jwt: { issuer: i, shared: false } } } }", "providers.p.proof", "maxProperties"},
		{"shared not stated", "providers: { p: { proof: { jwt: { issuer: i, discovery: true } } } }", "providers.p.proof.jwt", "missing property 'shared'"},
		{"param for a boolean", "providers: { p: { params: { s: { type: string, default: x } }, proof: { jwt: { issuer: i, discovery: true, shared: $s } } } }", "providers.p.proof.jwt.shared", "want boolean"},
		{"relative exec command", "providers: { p: { proof: { exec: { command: [verify], shared: false } } } }", "providers.p.proof.exec.command[0]", "does not match pattern"},
		{"bad grant permission", `grants: { g: { who: "spiffe://example.org/a", can: [admin], on: [/] } }`, "grants.g.can[0]", "value must be one of"},
		{"repeated grant permission", `grants: { g: { who: "spiffe://example.org/a", can: [read, read], on: [/] } }`, "grants.g.can", "are equal"},
		{"claim path with an empty member", "origins: { a: { provider: kubernetes, require: [a//b] } }", "origins.a.require[0]", "does not match pattern"},
		{"dot-dot segment in a prefix", "origins: { a: { provider: keys, prefix: /a/.. } }", "origins.a.prefix", "does not match pattern"},
		{"dot segment in a prefix", "origins: { a: { provider: keys, prefix: /./a } }", "origins.a.prefix", "does not match pattern"},
		{"trailing slash in a prefix", "origins: { a: { provider: keys, prefix: /a/ } }", "origins.a.prefix", "does not match pattern"},
		{"dot-dot scope", `grants: { g: { who: "spiffe://example.org/a", can: [read], on: [/a/..] } }`, "grants.g.on[0]", "does not match pattern"},
		{"dot-dot member", `origins: { a: { provider: keys, members: { "..": { keys: [x] } } } }`, "origins.a.members", "does not match pattern"},
		{"empty pattern", `origins: { a: { provider: kubernetes, match: { sub: "" } } }`, "origins.a.match.sub", "minLength"},
		{"empty pattern in a list", `origins: { a: { provider: kubernetes, deny: { sub: [x, ""] } } }`, "origins.a.deny.sub[1]", "minLength"},
		{"empty audience pattern", `origins: { a: { provider: kubernetes, audiences: [""] } }`, "origins.a.audiences[0]", "minLength"},
		{"bad tilde in a claim path", "origins: { a: { provider: kubernetes, require: [a~2b] } }", "origins.a.require[0]", "does not match pattern"},
		{"grants is now delegate", `grants: { g: { who: "spiffe://example.org/a", can: [grants], on: [/] } }`, "grants.g.can[0]", "value must be one of"},
		{"empty svid_types", "origins: { a: { provider: keys, svid_types: [] } }", "origins.a.svid_types", "minItems"},
		{"unknown svid type", "origins: { a: { provider: keys, svid_types: [saml] } }", "origins.a.svid_types[0]", "value must be one of"},
		{"repeated svid type", "origins: { a: { provider: keys, svid_types: [jwt, jwt] } }", "origins.a.svid_types", "are equal"},
		{"svid_types not a list", "origins: { a: { provider: keys, svid_types: x509 } }", "origins.a.svid_types", "want array"},
		{"empty provider svid_types", "providers: { p: { proof: { keys: {} }, svid_types: [] } }", "providers.p.svid_types", "minItems"},
		{"unknown provider svid type", "providers: { p: { proof: { keys: {} }, svid_types: [x509, x500] } }", "providers.p.svid_types[1]", "value must be one of"},
		{"repeated provider svid type", "providers: { p: { proof: { keys: {} }, svid_types: [x509, x509] } }", "providers.p.svid_types", "are equal"},
		{"match on a dotted claim", "origins: { a: { provider: kubernetes, match: { kubernetes.io/namespace: [] } } }", `origins.a.match["kubernetes.io/namespace"]`, "minItems"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseState([]byte(tt.doc))
			var problems Problems
			if !errors.As(err, &problems) {
				t.Fatalf("want problems, got %v", err)
			}
			if !hasProblem(problems, tt.path, tt.msg) {
				t.Errorf("want a problem at %q containing %q, got:\n%v", tt.path, tt.msg, problems)
			}
		})
	}
}

func TestParseSVIDTypes(t *testing.T) {
	doc := `
origins:
  a: { provider: p, svid_types: [x509] }
  b: { provider: p }
providers:
  p: { proof: { keys: {} }, svid_types: [jwt, x509] }
`
	st, err := ParseState([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Origins["a"].SVIDTypes; len(got) != 1 || got[0] != "x509" {
		t.Errorf("origin svid_types = %v", got)
	}
	if got := st.Origins["b"].SVIDTypes; got != nil {
		t.Errorf("an origin without svid_types has %v", got)
	}
	if got := st.Providers["p"].SVIDTypes; len(got) != 2 || got[0] != "jwt" || got[1] != "x509" {
		t.Errorf("provider svid_types = %v", got)
	}
}

func TestParseRefusesWhatJSONCannotSay(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":           "",
		"comment only":    "# nothing\n",
		"two documents":   "origins: {}\n---\norigins: {}\n",
		"duplicate key":   "origins: {}\norigins: {}\n",
		"duplicate JSON":  `{"origins": {}, "origins": {}}`,
		"integer key":     "origins: { 1: { provider: keys } }",
		"merge key":       "x: &x { provider: keys }\norigins: { a: { <<: *x } }",
		"custom tag":      "origins: !thing {}",
		"binary":          "origins: !!binary aGk=",
		"not a number":    "origins: { a: { provider: .nan } }",
		"over a mebibyte": "providers: { p: { description: " + strings.Repeat("x", MaxStateSize) + ", proof: { keys: {} } } }",
	} {
		if _, err := ParseState([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// Aliases let a small document expand without bound, and JSON cannot say
// them anyway.
func TestParseRefusesAnchorsAndAliases(t *testing.T) {
	for name, doc := range map[string]string{
		"alias":        "origins:\n  a: &origin { provider: keys }\n  b: *origin\n",
		"anchor alone": "origins: &o {}\n",
		"aliased key":  "x: &k a\norigins: { *k : { provider: keys } }\n",
		"amplifier":    "a: &a " + strings.Repeat("x", 1000) + "\nb: [" + strings.Repeat("*a, ", 2000) + "*a]\n",
	} {
		_, err := ParseState([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "anchors and aliases are not supported") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The size limit applies before parsing, whatever the document would
	// shrink to.
	huge := "# " + strings.Repeat("x", MaxStateSize) + "\norigins: {}\n"
	if _, err := ParseState([]byte(huge)); err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Errorf("oversized input: %v", err)
	}
}

func TestStringsJSON(t *testing.T) {
	for _, s := range []Strings{One("a"), List("a", "b"), List()} {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back Strings
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if back.List != s.List || len(back.Values) != len(s.Values) {
			t.Errorf("%s round-tripped to %+v", data, back)
		}
	}
	if err := json.Unmarshal([]byte("42"), new(Strings)); err == nil {
		t.Error("a number unmarshalled into Strings")
	}
}

// The schema library reuses the buffer behind a property name failure's
// location, so which path it reported depended on map order. Repeating the
// check with many siblings exposes it.
func TestPropertyNameProblemsAreLocatedStably(t *testing.T) {
	doc := `origins: { a: { provider: keys, prefix: /a, name: x, require: [], audiences: [x], members: { "..": { keys: [x] } } }, b: { provider: keys }, c: { provider: keys } }`
	for range 50 {
		_, err := ParseState([]byte(doc))
		var problems Problems
		if !errors.As(err, &problems) || !hasProblem(problems, "origins.a.members", "'..' does not match pattern") {
			t.Fatalf("problems = %v", err)
		}
	}
	_, err := ParseState([]byte("providers: { p: { params: { Bad: { type: string, default: x } }, proof: { keys: {} } } }"))
	var problems Problems
	if !errors.As(err, &problems) || !hasProblem(problems, "providers.p.params", "'Bad' does not match pattern") {
		t.Errorf("problems = %v", err)
	}
}
