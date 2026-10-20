package state

import (
	"crypto/elliptic"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestExampleStateIsValid(t *testing.T) {
	data, err := os.ReadFile("testdata/state.yaml")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseState(data)
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(st, testSettings())
	wantValid(t, r)
	if len(r.Origins) != 4 || len(r.Grants) != 2 || len(r.Skipped) != 0 {
		t.Errorf("origins %d, grants %d, skipped %v", len(r.Origins), len(r.Grants), r.Skipped)
	}
	kube := r.Origins["kube"]
	if kube.JWT.Audience != "https://issuer.example.org/origins/kube" || !kube.JWT.OriginAudience {
		t.Errorf("kube audience = %s", kube.JWT.Audience)
	}
	if kube.JWT.MaxTokenLifetime != DefaultMaxTokenLifetime || r.Origins["partner"].JWT.MaxTokenLifetime.String() != "15m0s" {
		t.Error("max token lifetimes are wrong")
	}
	if len(r.Origins["vms"].Members["billing"]) != 1 {
		t.Error("member billing has no key")
	}
}

const k8sOrigin = `
  kube: { provider: kubernetes }`

func TestValidationRules(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		// path and msg locate the expected problem; both empty means the
		// document is valid.
		path, msg string
	}{
		// Providers and overrides.
		{"unknown provider", `
origins:
  a: { provider: nope }`, "origins.a.provider", "no provider named nope"},
		{"shipped name without overrides", `
providers:
  keys: { proof: { keys: {} }, name: "{member}" }`, "providers.keys", "set overrides: true"},
		{"overrides without a shipped provider", `
providers:
  mine: { overrides: true, proof: { keys: {} } }`, "providers.mine.overrides", "no shipped provider is named mine"},
		{"override", `
providers:
  keys: { overrides: true, proof: { keys: {} }, name: "{member}" }`, "", ""},

		// Prefixes and names.
		{"prefixes overlap", `
origins:
  a: { provider: keys, prefix: /x }
  b: { provider: keys, prefix: /x/y }`, "origins.b", "prefix /x/y overlaps prefix /x of origin a"},
		{"equal prefixes", `
origins:
  a: { provider: keys, prefix: /x }
  b: { provider: keys, prefix: /x }`, "origins.b", "overlaps"},
		{"prefixes share text but not segments", `
origins:
  a: { provider: keys, prefix: /a }
  b: { provider: keys, prefix: /ab }`, "", ""},
		{"default prefix overlaps", `
origins:
  a: { provider: keys }
  b: { provider: keys, prefix: /a/b }`, "origins.b", "overlaps prefix /a"},
		{"root prefix overlaps everything", `
origins:
  a: { provider: keys, prefix: / }
  b: { provider: keys }`, "origins.b", "overlaps prefix /"},
		{"root prefix needs a name", `
origins:
  a: { provider: keys, prefix: /, name: "" }`, "origins.a", "prefix / needs a name template"},
		{"empty name is the prefix alone", `
origins:
  billing: { provider: keys, name: "" }`, "", ""},
		{"template with a partial placeholder", `
origins:
  a: { provider: keys, name: "a{member}" }`, "origins.a.name", "fill a whole segment"},
		{"template with an empty part", `
origins:
  a: { provider: keys, name: "x//{member}" }`, "origins.a.name", "not a path segment"},
		{"template ending in /", `
origins:
  a: { provider: keys, name: "{member}/" }`, "origins.a.name", "ends with /"},
		{"keys template with a claim", `
origins:
  a: { provider: keys, name: "{sub}" }`, "origins.a.name", "only placeholder is {member}"},
		{"keys template with a bad literal", `
origins:
  a: { provider: keys, name: "a b" }`, "origins.a.name", "not a path segment"},
		{"jwt template with nested claim paths", k8sOrigin[0:0] + `
origins:
  a: { provider: kubernetes, name: "{kubernetes.io/pod/name}/x" }`, "", ""},
		{"SPIFFE ID too long", `
origins:
  a: { provider: keys, prefix: /` + strings.Repeat(strings.Repeat("x", 255)+"/", 8) + `y }`, "origins.a", "more than the 2048 allowed"},

		// Admission belongs to jwt and exec origins, members to keys origins.
		{"keys origin with require", `
origins:
  a: { provider: keys, require: [sub] }`, "origins.a", "a keys origin has no require, match or deny"},
		{"keys provider with match", `
providers:
  k: { proof: { keys: {} }, match: { sub: x } }`, "providers.k", "a keys proof takes no require, match or deny"},
		{"jwt origin with members", `
origins:
  kube: { provider: kubernetes, members: { m: { keys: ["x"] } } }`, "origins.kube.members", "only a keys origin has members"},
		{"origin narrows admission", `
origins:
  kube: { provider: kubernetes, require: [kubernetes.io/serviceaccount/uid], match: { sub: "system:*" }, deny: { sub: "*:default" } }`, "", ""},

		// Audience uniqueness and the jwt proof.
		{"same issuer and audience", `
providers:
  p:
    proof: { jwt: { issuer: "https://idp.example", audience: shared-aud, jwks_uri: "https://idp.example/k", shared: false } }
origins:
  a: { provider: p }
  b: { provider: p }`, "origins.b", "origin a already takes tokens from https://idp.example with audience shared-aud"},
		{"same issuer, origin audiences", `
providers:
  p:
    proof: { jwt: { issuer: "https://idp.example", jwks_uri: "https://idp.example/k", shared: false } }
origins:
  a: { provider: p }
  b: { provider: p }`, "", ""},
		{"no key source", `
providers:
  p: { proof: { jwt: { issuer: "https://idp.example", shared: false } } }`, "providers.p.proof.jwt", "set exactly one of jwks, jwks_uri, jwks_file and discovery"},
		{"two key sources", `
providers:
  p: { proof: { jwt: { issuer: "https://idp.example", jwks_uri: "https://idp.example/k", discovery: true, shared: false } } }`, "providers.p.proof.jwt", "set exactly one"},
		{"discovery needs https", `
providers:
  p: { proof: { jwt: { issuer: "http://idp.example", discovery: true, shared: false } } }`, "providers.p.proof.jwt.issuer", "discovery needs an https issuer"},
		{"jwks_uri must be https", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "http://idp.example/k", shared: false } } }`, "providers.p.proof.jwt.jwks_uri", "must be an https URL"},
		{"inline jwks without keys", `
providers:
  p: { proof: { jwt: { issuer: i, jwks: { keys: [] }, shared: false } } }`, "providers.p.proof.jwt.jwks", "has no keys"},
		{"max token lifetime over a day", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://idp.example/k", shared: false, max_token_lifetime: 25h } } }`, "providers.p.proof.jwt.max_token_lifetime", "longer than the 24h allowed"},
		{"max token lifetime of a day", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://idp.example/k", shared: false, max_token_lifetime: 1440m } } }`, "", ""},
		{"own issuer as upstream", `
providers:
  p: { proof: { jwt: { issuer: "https://issuer.example.org", jwks_uri: "https://issuer.example.org/jwks", shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.issuer", "cannot be its own upstream"},

		// Local files.
		{"jwks_file not allowed", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_file: /etc/jwks.json, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.jwks_file", "not among the files"},
		{"ca_file not allowed", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://idp.example/k", ca_file: /etc/ssl/ca.pem, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.ca_file", "not among the files"},
		{"bearer token with a file key source", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt, bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }`, "providers.p.proof.jwt", "only apply to keys fetched over the network"},
		{"bearer token file not allowed", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://idp.example/k", bearer_token_file: /etc/token, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.bearer_token_file", "this bearer token file is not allowed by the issuer's settings"},
		{"bearer token to another host", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://evil.example/k", bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.jwks_uri", "do not allow the bearer token file to be sent to evil.example"},
		{"bearer token to another host by parameter", `
providers:
  p:
    params: { uri: { type: string, default: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks" } }
    proof: { jwt: { issuer: i, jwks_uri: $uri, bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } }
origins:
  a: { provider: p }
  b: { provider: p, with: { uri: "https://evil.example/k" } }`, "origins.b.with.uri", "sent to evil.example"},
		{"bearer token to another path of the allowed host", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://kubernetes.default.svc.cluster.local/api/v1/secrets", bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.jwks_uri", "on /api/v1/secrets"},
		{"bearer token with a query", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks?x=1", bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.jwks_uri", "do not allow"},
		{"bearer token to the discovery issuer's host", `
providers:
  p: { proof: { jwt: { issuer: "https://kubernetes.default.svc.cluster.local", discovery: true, bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }
origins:
  a: { provider: p }`, "", ""},
		{"bearer token with a port is another host", `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://kubernetes.default.svc.cluster.local:6443/k", bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token, shared: false } } }
origins:
  a: { provider: p }`, "providers.p.proof.jwt.jwks_uri", "sent to kubernetes.default.svc.cluster.local:6443"},

		// Shared upstreams.
		{"shared upstream without a pin", `
origins:
  a: { provider: oidc, with: { issuer: "https://idp.example", owner_claims: [org] } }`, "origins.a.match", "https://idp.example is a shared upstream: admission needs a match entry with only exact patterns on one of org"},
		{"shared upstream pinned", `
origins:
  a: { provider: oidc, with: { issuer: "https://idp.example", owner_claims: [org] }, match: { org: [acme, initech] } }`, "", ""},
		{"shared upstream pinned with a wildcard", `
origins:
  a: { provider: oidc, with: { issuer: "https://idp.example", owner_claims: [org] }, match: { org: "acme*" } }`, "origins.a.match", "only exact patterns"},
		{"shared upstream pinned on another claim", `
origins:
  a: { provider: oidc, with: { issuer: "https://idp.example", owner_claims: [org] }, match: { team: acme } }`, "origins.a.match", "one of org"},
		{"shared upstream without owner claims", `
origins:
  a: { provider: oidc, with: { issuer: "https://idp.example", owner_claims: [] } }`, "origins.a.with.owner_claims", "needs owner claims"},
		{"shared provider without owner claims", `
providers:
  p: { proof: { jwt: { issuer: "https://idp.example", discovery: true, shared: true } } }
origins:
  a: { provider: p, match: { org: acme } }`, "providers.p.proof.jwt.owner_claims", "needs owner claims"},
		{"forbidden owner claim", `
providers:
  p: { proof: { jwt: { issuer: "https://idp.example", discovery: true, shared: true, owner_claims: [azp] } } }`, "providers.p.proof.jwt.owner_claims[0]", "azp cannot be an owner claim"},
		{"well-known issuer marked not shared", `
providers:
  p: { proof: { jwt: { issuer: "https://gitlab.com", discovery: true, shared: false } } }
origins:
  a: { provider: p }`, "origins.a.match", "https://gitlab.com is a well-known shared upstream"},
		{"well-known issuer pinned on its own owner claims", `
providers:
  p: { proof: { jwt: { issuer: "https://gitlab.com", discovery: true, shared: false, owner_claims: [team] } } }
origins:
  a: { provider: p, match: { team: x } }`, "origins.a.match", "one of namespace_id, project_id"},
		{"well-known issuer subtree", `
providers:
  p: { proof: { jwt: { issuer: "https://token.actions.githubusercontent.com/acme", discovery: true, shared: false } } }
origins:
  a: { provider: p, match: { enterprise_id: "17" } }`, "", ""},
		{"well-known subtree is by segment", `
providers:
  p: { proof: { jwt: { issuer: "https://token.actions.githubusercontent.community", discovery: true, shared: false } } }
origins:
  a: { provider: p }`, "", ""},
		{"exact well-known entries have no subtree", `
providers:
  p: { proof: { jwt: { issuer: "https://gitlab.com/x", discovery: true, shared: false } } }
origins:
  a: { provider: p }`, "", ""},
		{"github provider", `
origins:
  ci: { provider: github, with: { owner_id: "4711", refs: ["refs/heads/main"] } }`, "", ""},
		{"github provider without refs", `
origins:
  ci: { provider: github, with: { owner_id: "4711" } }`, "origins.ci.with", "parameter refs of provider github is required"},
		{"github provider with an empty owner", `
origins:
  ci: { provider: github, with: { owner_id: "", refs: ["refs/heads/main"] } }`, "origins.ci.with.owner_id", "a pattern cannot be empty"},
		{"github provider with a wildcard owner", `
origins:
  ci: { provider: github, with: { owner_id: "47*", refs: ["refs/heads/main"] } }`, "origins.ci.match", "only exact patterns"},
		{"gitlab provider", `
origins:
  ci: { provider: gitlab, with: { namespace_id: "42", project_ids: ["7", "8"], refs: [main] } }`, "", ""},

		// Exec proofs.
		{"exec command not installed", `
providers:
  v: { proof: { exec: { command: [/usr/local/bin/verify], shared: false } }, name: "{sub}" }
origins:
  a: { provider: v }`, "providers.v.proof.exec.command", "not among the verifiers"},
		{"exec command not a clean path", `
providers:
  v: { proof: { exec: { command: [/usr/local/../bin/verify], shared: false } } }`, "providers.v.proof.exec.command[0]", "clean absolute path"},
		{"exec command with a dot segment", `
providers:
  v: { proof: { exec: { command: [/usr/local/bin/./verify], shared: false } } }`, "providers.v.proof.exec.command[0]", "clean absolute path"},
		{"exec command with a repeated slash", `
providers:
  v: { proof: { exec: { command: [/usr/local//bin/verify], shared: false } } }`, "providers.v.proof.exec.command[0]", "clean absolute path"},
		{"exec command with a trailing slash", `
providers:
  v: { proof: { exec: { command: [/usr/local/bin/verify/], shared: false } } }`, "providers.v.proof.exec.command[0]", "clean absolute path"},

		// Empty patterns.
		{"empty deny pattern from a parameter", `
origins:
  k: { provider: kubernetes, with: { deny_namespaces: [""] } }`, "origins.k.with.deny_namespaces", "a pattern cannot be empty"},
		{"empty audience pattern from a parameter", `
providers:
  p: { params: { auds: { type: list, required: true } }, proof: { keys: {} }, audiences: $auds, name: "{member}" }
origins:
  a: { provider: p, with: { auds: ["https://api.example.org", ""] } }`, "origins.a.with.auds", "a pattern cannot be empty"},

		{"exec timeout over 30s", `
providers:
  v: { proof: { exec: { command: [/usr/local/bin/verify], shared: false, timeout: 31s } } }`, "providers.v.proof.exec.timeout", "longer than the 30s allowed"},
		{"exec with a forbidden owner claim", `
providers:
  v: { proof: { exec: { command: [/usr/local/bin/verify], shared: true, owner_claims: [iss] } } }`, "providers.v.proof.exec.owner_claims[0]", "iss cannot be an owner claim"},

		// Grants.
		{"grant in another trust domain", `
grants:
  g: { who: "spiffe://other.org/a", can: [read], on: [/] }`, "grants.g.who", "not in trust domain example.org"},
		{"grant with ** in the middle", `
grants:
  g: { who: "spiffe://example.org/**/a", can: [read], on: [/] }`, "grants.g.who", "** can only be the last segment"},
		{"grant", `
grants:
  g: { who: "spiffe://example.org/ops/*", can: [read], on: [/a, /b] }`, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := check(t, tt.doc)
			if tt.path == "" && tt.msg == "" {
				wantValid(t, r)
				return
			}
			wantProblem(t, r, tt.path, tt.msg)
		})
	}
}

func TestOverrideReplacesShippedProvider(t *testing.T) {
	r := check(t, `
providers:
  keys:
    overrides: true
    description: Every member shares one identity.
    proof: { keys: {} }
    name: shared
origins:
  vms: { provider: keys }
`)
	wantValid(t, r)
	if len(r.Overrides) != 1 || r.Overrides[0] != "keys" {
		t.Errorf("overrides = %v", r.Overrides)
	}
	if got := r.Origins["vms"].Template.String(); got != "shared" {
		t.Errorf("the origin uses template %q, not the override's", got)
	}
}

func TestSettingsAllowFiles(t *testing.T) {
	doc := `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://idp.internal/k", ca_file: /etc/idp/ca.pem, bearer_token_file: /etc/idp/token, shared: false } } }
  q: { proof: { jwt: { issuer: j, jwks_file: /etc/idp/jwks.json, shared: false } } }
origins:
  a: { provider: p }
  b: { provider: q }
`
	r := check(t, doc)
	for _, path := range []string{"providers.p.proof.jwt.ca_file", "providers.p.proof.jwt.bearer_token_file", "providers.q.proof.jwt.jwks_file"} {
		wantProblem(t, r, path, "not")
	}
	s := testSettings()
	s.ReadableFiles = []string{"/etc/idp/ca.pem", "/etc/idp/jwks.json"}
	s.BearerTokenFiles = []BearerTokenFile{{Path: "/etc/idp/token", Hosts: []string{"IDP.internal"}}}
	wantValid(t, checkWith(t, doc, s))

	// The defaults allow exactly what the shipped kubernetes provider needs.
	wantValid(t, check(t, "origins:"+k8sOrigin))
	s.ReadableFiles = nil
	wantProblem(t, checkWith(t, "origins:"+k8sOrigin, s), "origins.kube.provider", "shipped provider kubernetes, proof.jwt.ca_file")
}

func TestExecOrigins(t *testing.T) {
	doc := `
providers:
  cloud:
    params: { account: { type: string, required: true } }
    proof:
      exec:
        command: [/usr/local/libexec/verify-cloud, --strict]
        shared: true
        owner_claims: [account]
    match: { account: $account }
    name: "{role}"
origins:
  aws-prod: { provider: cloud, with: { account: "123456789012" } }
  aws-dev: { provider: cloud, with: { account: "210987654321" }, require: [role] }
`
	s := testSettings()
	wantProblem(t, checkWith(t, doc, s), "providers.cloud.proof.exec.command", "not among the verifiers")

	s.Verifiers = [][]string{{"/usr/local/libexec/verify-cloud"}}
	wantProblem(t, checkWith(t, doc, s), "providers.cloud.proof.exec.command", "exactly these arguments")

	s.Verifiers = [][]string{{"/usr/local/libexec/verify-cloud", "--strict"}}
	r := checkWith(t, doc, s)
	wantValid(t, r)
	e := r.Origins["aws-prod"]
	if e.Kind != KindExec || e.Exec.Timeout != DefaultExecTimeout || e.Exec.Audience != "https://issuer.example.org/origins/aws-prod" {
		t.Errorf("expanded exec = %+v", e.Exec)
	}
	if e.Exec.Params["account"].Values[0] != "123456789012" {
		t.Errorf("params = %v", e.Exec.Params)
	}
	id, err := e.Admit(td, map[string]any{"account": "123456789012", "role": "deployer"})
	if err != nil || id.String() != "spiffe://example.org/aws-prod/deployer" {
		t.Errorf("admit = %v, %v", id, err)
	}

	unpinned := strings.Replace(doc, "    match: { account: $account }\n", "", 1)
	wantProblem(t, checkWith(t, unpinned, s), "origins.aws-prod.match", "the verifier accepts proofs anyone can obtain")
	noOwners := strings.Replace(doc, "        owner_claims: [account]\n", "", 1)
	wantProblem(t, checkWith(t, noOwners, s), "providers.cloud.proof.exec.owner_claims", "needs owner claims")
}

func TestMembers(t *testing.T) {
	p256 := ecKey(t, elliptic.P256())
	p384 := ecKey(t, elliptic.P384())
	rsa2048 := rsaKey(t, 2048)
	rsa1024 := rsaKey(t, 1024)
	jwk := func(key any, alg string) string {
		data, err := json.Marshal(jose.JSONWebKey{Key: key, Algorithm: alg})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	jwkUse := func(key any, use string) string {
		data, err := json.Marshal(jose.JSONWebKey{Key: key, Use: use})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	doc := func(keys ...string) string {
		return "origins:\n  vms:\n    provider: keys\n    members:\n      m:\n        keys: [" + strings.Join(keys, ", ") + "]\n"
	}
	quote := func(s string) string {
		data, _ := json.Marshal(s)
		return string(data)
	}
	tests := []struct {
		name, key, msg string
	}{
		{"P-256 PEM", quote(pemKey(t, &p256.PublicKey)), ""},
		{"RSA 2048 PEM", quote(pemKey(t, &rsa2048.PublicKey)), ""},
		{"P-256 JWK", jwk(&p256.PublicKey, "ES256"), ""},
		{"RSA JWK without alg", jwk(&rsa2048.PublicKey, ""), ""},
		{"P-384", quote(pemKey(t, &p384.PublicKey)), "want P-256"},
		{"RSA 1024", quote(pemKey(t, &rsa1024.PublicKey)), "too small"},
		{"private JWK", jwk(p256, "ES256"), `private member "d"`},
		{"JWK with a mismatched alg", jwk(&p256.PublicKey, "RS256"), "want ES256"},
		{"RSA JWK with a mismatched alg", jwk(&rsa2048.PublicKey, "ES256"), "want RS256"},
		{"JWK for signing", jwkUse(&p256.PublicKey, "sig"), ""},
		{"JWK for encryption", jwkUse(&p256.PublicKey, "enc"), `use "enc", want sig`},
		{"not PEM", quote("hello"), "no PEM block"},
		{"two PEM blocks", quote(pemKey(t, &p256.PublicKey) + pemKey(t, &p256.PublicKey)), "more than one PEM block"},
		{"symmetric JWK", `{"kty": "oct", "k": "c2VjcmV0"}`, "private key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := check(t, doc(tt.key))
			if tt.msg == "" {
				wantValid(t, r)
				if n := len(r.Origins["vms"].Members["m"]); n != 1 {
					t.Errorf("member has %d keys", n)
				}
				return
			}
			wantProblem(t, r, "origins.vms.members.m.keys[0]", tt.msg)
		})
	}

	key := quote(pemKey(t, &p256.PublicKey))
	if _, err := ParseState([]byte(doc(strings.Repeat(key+", ", 10) + key))); err == nil {
		t.Error("a member with 11 keys parsed")
	}
}

func TestSingleObjectChecks(t *testing.T) {
	s := testSettings()
	o := &Origin{Provider: "keys", Prefix: "/a"}
	r := ValidateOrigin("a", o, nil, s)
	wantValid(t, r)
	if len(r.Skipped) != len(crossObjectChecks) {
		t.Errorf("skipped = %v", r.Skipped)
	}
	if r.Origins["a"] == nil {
		t.Error("the origin did not expand")
	}

	bad := &Origin{Provider: "partner"}
	wantProblem(t, ValidateOrigin("a", bad, nil, s), "origins.a.provider", "no provider named partner")
	p := &Provider{Proof: Proof{JWT: &JWTProof{Issuer: "https://idp.example", JWKSURI: "https://idp.example/k", Shared: true}}}
	wantProblem(t, ValidateOrigin("a", bad, map[string]*Provider{"partner": p}, s), "providers.partner.proof.jwt.owner_claims", "needs owner claims")
	wantProblem(t, ValidateOrigin("Bad", o, nil, s), "origins", "'Bad' does not match pattern")

	// A provider on its own is expanded with its defaults, so settings
	// checks apply, but the owner rule, which depends on the origin, is
	// skipped.
	p.Proof.JWT.OwnerClaims = &Strings{Values: []string{"org"}, List: true}
	p.Proof.JWT.CAFile = "/etc/ca.pem"
	r = ValidateProvider("partner", p, s)
	wantProblem(t, r, "providers.partner.proof.jwt.ca_file", "not among the files")
	if !strings.Contains(strings.Join(r.Skipped, "\n"), "pin the owner") {
		t.Errorf("skipped = %v", r.Skipped)
	}
	required := &Provider{Params: map[string]*Param{"org": {Type: ParamString, Required: true}}, Proof: Proof{Keys: &KeysProof{}}}
	r = ValidateProvider("orgs", required, s)
	wantValid(t, r)
	if !strings.Contains(strings.Join(r.Skipped, "\n"), "required parameters [org]") {
		t.Errorf("skipped = %v", r.Skipped)
	}
}

func TestSettingsAreChecked(t *testing.T) {
	for _, s := range []Settings{
		{TrustDomain: td},
		DefaultSettings("https://issuer.example.org/", td),
		DefaultSettings("ftp://issuer.example.org", td),
		DefaultSettings("https://issuer.example.org?x=1", td),
		{Issuer: testIssuer},
	} {
		wantProblem(t, Validate(&State{}, s), "settings", "")
	}
}

// Validate checks a state built in Go as it would a parsed one, and never
// panics on one.
func TestValidateGoBuiltStates(t *testing.T) {
	tests := []struct {
		name string
		st   *State
		msg  string
	}{
		{"nil state", nil, "there is no state"},
		{"empty audiences", &State{Providers: map[string]*Provider{"p": {Proof: Proof{Keys: &KeysProof{}}, Audiences: &Strings{}}}}, "exactly one value"},
		{"unknown svid type", &State{Origins: map[string]*Origin{"a": {Provider: "keys", SVIDTypes: []string{"saml"}}}}, "value must be one of"},
		{"empty svid_types", &State{Origins: map[string]*Origin{"a": {Provider: "keys", SVIDTypes: []string{}}}}, "minItems"},
		{"repeated svid type", &State{Providers: map[string]*Provider{"p": {Proof: Proof{Keys: &KeysProof{}}, SVIDTypes: []string{"jwt", "jwt"}}}}, "are equal"},
		{"nil origin", &State{Origins: map[string]*Origin{"a": nil}}, "want object"},
		{"nil provider", &State{Providers: map[string]*Provider{"p": nil}}, "want object"},
		{"nil param", &State{Providers: map[string]*Provider{"p": {Proof: Proof{Keys: &KeysProof{}}, Params: map[string]*Param{"x": nil}}}}, "want object"},
		{"nil grant", &State{Grants: map[string]*Grant{"g": nil}}, "want object"},
		{"no proof", &State{Providers: map[string]*Provider{"p": {}}}, "minProperties"},
		{"bad match key", &State{Origins: map[string]*Origin{"a": {Provider: "kubernetes", Match: map[string]Strings{"a//b": One("x")}}}}, "does not match pattern"},
		{"empty deny pattern", &State{Origins: map[string]*Origin{"a": {Provider: "kubernetes", Deny: map[string]Strings{"sub": One("")}}}}, "minLength"},
		{"bad member key JSON", &State{Origins: map[string]*Origin{"a": {Provider: "keys", Members: map[string]*Member{"m": {Keys: []json.RawMessage{json.RawMessage("{")}}}}}}, "cannot be encoded"},
		{"oversized", &State{Providers: map[string]*Provider{"p": {Proof: Proof{Keys: &KeysProof{}}, Description: strings.Repeat("x", MaxStateSize)}}}, "more than the"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Validate(tt.st, testSettings())
			if len(r.Problems) == 0 || !strings.Contains(r.Problems.Error(), tt.msg) {
				t.Errorf("problems = %v, want one containing %q", r.Problems, tt.msg)
			}
			if len(r.Origins) != 0 {
				t.Error("origins of an invalid state were returned")
			}
		})
	}
}

// An origin's own match and deny entries are checked in Go too, not only by
// the schema.
func TestOriginConditionsCheckedInGo(t *testing.T) {
	v := newValidator(&State{}, testSettings(), false)
	x := &expansion{v: v, name: "a", path: "origins.a"}
	x.checkConditions("origins.a.match", map[string]Strings{"a~2": One("x"), "sub": List("ok", "")})
	if !hasProblem(v.problems, `origins.a.match["a~2"]`, "~ must be followed by 0 or 1") || !hasProblem(v.problems, "origins.a.match.sub[1]", "a pattern cannot be empty") {
		t.Errorf("problems = %v", v.problems)
	}
}

func TestNothingOfAnInvalidStateIsUsable(t *testing.T) {
	r := check(t, `
origins:
  good: { provider: keys }
  bad: { provider: nope }
grants:
  g: { who: "spiffe://example.org/good/x", can: [read], on: [/] }
`)
	if len(r.Problems) == 0 || len(r.Origins) != 0 || r.Grants != nil {
		t.Errorf("problems %v, origins %v, grants %v", r.Problems, r.Origins, r.Grants)
	}
}

func TestIssuerGuards(t *testing.T) {
	tests := []struct {
		name, audience, issuer, path, msg string
	}{
		{"own issuer with a trailing slash", "", "https://issuer.example.org/", "providers.p.proof.jwt.issuer", "cannot be its own upstream"},
		{"audience is the issuer URL", "https://issuer.example.org", "", "providers.p.proof.jwt.audience", "the only such audience allowed is the origin audience https://issuer.example.org/origins/a"},
		{"audience is the issuer URL with a slash", "https://issuer.example.org/", "", "providers.p.proof.jwt.audience", "is the issuer URL or under it"},
		{"audience is the management endpoint", "https://issuer.example.org/manage", "", "providers.p.proof.jwt.audience", "is the issuer URL or under it"},
		{"audience is another origin's", "https://issuer.example.org/origins/b", "", "providers.p.proof.jwt.audience", "is the issuer URL or under it"},
		{"audience is its own origin audience", "https://issuer.example.org/origins/a", "", "", ""},
		{"audience elsewhere", "https://api.example.org", "", "", ""},
		{"audience sharing the issuer's text", "https://issuer.example.org.evil", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := tt.issuer
			if issuer == "" {
				issuer = "https://idp.example"
			}
			doc := "providers:\n  p: { proof: { jwt: { issuer: \"" + issuer + "\", jwks_uri: \"https://idp.example/k\", shared: false"
			if tt.audience != "" {
				doc += ", audience: \"" + tt.audience + "\""
			}
			doc += " } } }\norigins:\n  a: { provider: p }\n"
			r := check(t, doc)
			if tt.path == "" {
				wantValid(t, r)
				return
			}
			wantProblem(t, r, tt.path, tt.msg)
		})
	}
}

// What a state writer learns about the operator's settings is limited to
// whether they allow what the state asks for.
func TestBearerProblemsKeepSettingsPrivate(t *testing.T) {
	s := testSettings()
	s.BearerTokenFiles = []BearerTokenFile{{Path: "/secret/path/token", Hosts: []string{"private-host.internal"}}}
	r := checkWith(t, `
providers:
  p: { proof: { jwt: { issuer: i, jwks_uri: "https://elsewhere.example/k", bearer_token_file: /secret/path/token, shared: false } } }
  q: { proof: { jwt: { issuer: j, jwks_uri: "https://elsewhere.example/k", bearer_token_file: /guess, shared: false } } }
origins:
  a: { provider: p }
  b: { provider: q }
`, s)
	if len(r.Problems) != 2 {
		t.Fatalf("problems = %v", r.Problems)
	}
	for _, p := range r.Problems {
		if strings.Contains(p.Message, "private-host") || strings.Contains(p.Message, "/secret") || strings.Contains(p.Message, "/guess") {
			t.Errorf("%s reveals the settings", p)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		s    string
		want time.Duration
		ok   bool
	}{
		{"90s", 90 * time.Second, true},
		{"30m", 30 * time.Minute, true},
		{"24h", 24 * time.Hour, true},
		{"1440m", 24 * time.Hour, true},
		{"86401s", 0, false},
		{"25h", 0, false},
		{"2562048h", 0, false},
		{"9223372036854775807s", 0, false},
		{"99999999999999999999999h", 0, false},
		{"0s", 0, false},
		{"01h", 0, false},
		{"1d", 0, false},
		{"h", 0, false},
		{"-1h", 0, false},
		{"1.5h", 0, false},
	}
	for _, tt := range tests {
		got, err := parseDuration(tt.s, maxMaxTokenLifetime)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("%s = %s, %v", tt.s, got, err)
		}
	}
}

func TestParamNames(t *testing.T) {
	wantValid(t, check(t, `
providers:
  p:
    params: { deny_namespaces: { type: list, default: [a] }, my-param_2: { type: string, default: x } }
    proof: { jwt: { issuer: $my-param_2, jwks_uri: "https://idp.example/k", shared: false } }
    deny: { ns: $deny_namespaces }
`))
	for _, bad := range []string{"Upper", "1st", "_x", strings.Repeat("a", 64)} {
		doc := "providers:\n  p: { params: { " + bad + ": { type: string, default: x } }, proof: { keys: {} } }\n"
		if _, err := ParseState([]byte(doc)); err == nil {
			t.Errorf("parameter name %q was accepted", bad)
		}
	}
}

func TestKubernetesIssuerParameter(t *testing.T) {
	r := check(t, `
origins:
  eks: { provider: kubernetes, with: { issuer: "https://oidc.eks.eu-north-1.amazonaws.com/id/ABC" } }
`)
	wantValid(t, r)
	if got := r.Origins["eks"].JWT.Issuer; got != "https://oidc.eks.eu-north-1.amazonaws.com/id/ABC" {
		t.Errorf("issuer = %s", got)
	}
}

func TestInlineJWKSRefusesPrivateMembers(t *testing.T) {
	for _, member := range privateJWKMembers {
		doc := `
providers:
  p: { proof: { jwt: { issuer: i, shared: false, jwks: { keys: [{ kty: EC, crv: P-256, x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", ` + member + `: "AAAA" }] } } } }
`
		wantProblem(t, check(t, doc), "providers.p.proof.jwt.jwks", `private member "`+member+`"`)
	}
}
