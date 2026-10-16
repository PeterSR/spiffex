package state

import (
	"slices"
	"testing"
)

// A provider of its own with a parameter in every field that takes one.
const paramProvider = `
providers:
  idp:
    params:
      issuer: { type: string, default: https://idp.example }
      aud: { type: string, default: idp-aud }
      uri: { type: string, default: https://idp.example/keys }
      owners: { type: list, default: [org_id] }
      org: { type: string, required: true }
      envs: { type: list, default: [prod, "stag*"] }
      deny-env: { type: string, default: lab }
      audiences: { type: list, default: ["https://*.example.org"] }
    proof:
      jwt:
        issuer: $issuer
        audience: $aud
        jwks_uri: $uri
        shared: true
        owner_claims: $owners
    match:
      org_id: $org
      env: $envs
      label: [fixed, $org, "price:$5"]
    deny:
      env: $deny-env
    audiences: $audiences
    name: "{sub}"
`

func TestSubstitution(t *testing.T) {
	r := check(t, paramProvider+`
origins:
  a:
    provider: idp
    with:
      org: "$issuer"
      envs: [qa]
`)
	wantValid(t, r)
	e := r.Origins["a"]
	if e == nil {
		t.Fatal("origin a did not expand")
	}
	j := e.JWT
	if j.Issuer != "https://idp.example" || j.Audience != "idp-aud" || j.JWKSURI != "https://idp.example/keys" {
		t.Errorf("jwt proof = %+v", j)
	}
	if j.OriginAudience {
		t.Error("idp-aud counts as the origin audience")
	}
	if !slices.Equal(j.OwnerClaims, []string{"org_id"}) || !j.Shared {
		t.Errorf("owner claims %v, shared %v", j.OwnerClaims, j.Shared)
	}
	want := []Condition{
		{Claim: "env", Patterns: []Pattern{"qa"}},
		// Text that came from a parameter is never substituted again.
		{Claim: "label", Patterns: []Pattern{"fixed", "$issuer", "price:$5"}},
		{Claim: "org_id", Patterns: []Pattern{"$issuer"}},
	}
	if !slices.EqualFunc(e.Match, want, func(a, b Condition) bool {
		return a.Claim == b.Claim && slices.Equal(a.Patterns, b.Patterns)
	}) {
		t.Errorf("match = %v, want %v", e.Match, want)
	}
	if len(e.Deny) != 1 || !slices.Equal(e.Deny[0].Patterns, []Pattern{"lab"}) {
		t.Errorf("deny = %v", e.Deny)
	}
	if !slices.Equal(e.Audiences, []Pattern{"https://*.example.org"}) {
		t.Errorf("audiences = %v", e.Audiences)
	}
}

func TestSubstitutionProblems(t *testing.T) {
	tests := []struct {
		name, doc, path, msg string
	}{
		{"missing required", paramProvider + `
origins:
  a: { provider: idp }`, "origins.a.with", "parameter org of provider idp is required"},
		{"unknown param", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, nope: y } }`, "origins.a.with.nope", "provider idp has no parameter nope"},
		{"list for a string", paramProvider + `
origins:
  a: { provider: idp, with: { org: [x] } }`, "origins.a.with.org", "want a string"},
		{"string for a list", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, envs: prod } }`, "origins.a.with.envs", "want a list"},
		{"bad value in a substituted URL", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, uri: "http://idp.example/keys" } }`, "origins.a.with.uri", "must be an https URL"},
		{"forbidden owner claim from a parameter", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, owners: [aud] } }`, "origins.a.with.owners", "aud cannot be an owner claim"},
		{"empty audience pattern from a parameter", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, audiences: [""] } }`, "origins.a.with.audiences", "cannot be empty"},
		{"own issuer from a parameter", paramProvider + `
origins:
  a: { provider: idp, with: { org: x, issuer: "https://issuer.example.org" } }`, "origins.a.with.issuer", "cannot be its own upstream"},
		{"undeclared reference", `
providers:
  p:
    proof: { jwt: { issuer: $nope, jwks_uri: "https://x.example/k", shared: false } }`, "providers.p.proof.jwt.issuer", "parameter nope is not declared"},
		{"list param in a string field", `
providers:
  p:
    params: { l: { type: list, default: [a] } }
    proof: { jwt: { issuer: $l, jwks_uri: "https://x.example/k", shared: false } }`, "providers.p.proof.jwt.issuer", "is a list, but a single string goes here"},
		{"list param as a list element", `
providers:
  p:
    params: { l: { type: list, default: [a] } }
    proof: { jwt: { issuer: i, jwks_uri: "https://x.example/k", shared: false } }
    match: { c: [x, $l] }`, "providers.p.match.c[1]", "is a list, but a single string goes here"},
		{"string param as owner claims", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { jwt: { issuer: i, jwks_uri: "https://x.example/k", shared: false, owner_claims: $s } }`, "providers.p.proof.jwt.owner_claims", "is a string, but a list goes here"},
		{"param in the name template", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { keys: {} }
    name: $s`, "providers.p.name", "$s is taken literally here"},
		{"param in require", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { jwt: { issuer: i, jwks_uri: "https://x.example/k", shared: false } }
    require: [$s]`, "providers.p.require[0]", "$s is taken literally here"},
		{"param as a claim path in match", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { jwt: { issuer: i, jwks_uri: "https://x.example/k", shared: false } }
    match: { $s: x }`, `providers.p.match["$s"]`, "$s is taken literally here"},
		{"param in a file field", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { jwt: { issuer: i, jwks_uri: "https://x.example/k", shared: false, ca_file: $s } }`, "providers.p.proof.jwt.ca_file", "$s is taken literally here"},
		{"param in an exec command", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { exec: { command: [/usr/bin/verify, $s], shared: false } }`, "providers.p.proof.exec.command[1]", "$s is taken literally here"},
		{"param in exec owner claims", `
providers:
  p:
    params: { s: { type: string, default: a } }
    proof: { exec: { command: [/usr/bin/verify], shared: false, owner_claims: [$s] } }`, "providers.p.proof.exec.owner_claims[0]", "$s is taken literally here"},
		{"required and default", `
providers:
  p:
    params: { s: { type: string, required: true, default: a } }
    proof: { keys: {} }`, "providers.p.params.s", "either required: true or a default"},
		{"neither required nor default", `
providers:
  p:
    params: { s: { type: string } }
    proof: { keys: {} }`, "providers.p.params.s", "either required: true or a default"},
		{"default of the wrong type", `
providers:
  p:
    params: { s: { type: list, default: a } }
    proof: { keys: {} }`, "providers.p.params.s.default", "want a list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantProblem(t, check(t, tt.doc), tt.path, tt.msg)
		})
	}
}

// A $ that is not a whole value naming a parameter is literal text.
func TestDollarIsLiteralElsewhere(t *testing.T) {
	r := check(t, `
providers:
  p:
    params: { org: { type: string, required: true } }
    proof: { jwt: { issuer: "https://idp.example", jwks_uri: "https://idp.example/keys", shared: false } }
    match: { org: $org, cost: ["$org.x", "$", "$$org", "x$org", "$Org"] }
origins:
  a: { provider: p, with: { org: acme } }
`)
	wantValid(t, r)
	if r.Origins["a"] == nil {
		t.Fatal("origin a did not expand")
	}
	got := r.Origins["a"].Match
	if len(got) != 2 || !slices.Equal(got[0].Patterns, []Pattern{"$org.x", "$", "$$org", "x$org", "$Org"}) || !slices.Equal(got[1].Patterns, []Pattern{"acme"}) {
		t.Errorf("match = %v", got)
	}
}
