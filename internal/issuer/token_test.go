package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
	"github.com/PeterSR/spiffex/internal/verifier"
)

// The test binary doubles as an exec verifier: started with the argument
// verifier, it reads the request on standard input and answers with claims
// taken from the proof.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "verifier" {
		os.Exit(fakeVerifier())
	}
	os.Exit(m.Run())
}

func fakeVerifier() int {
	var in struct {
		SubjectToken string `json:"subject_token"`
		Audience     string `json:"audience"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return 2
	}
	switch in.SubjectToken {
	case "fail":
		fmt.Fprint(os.Stderr, "the proof is forged")
		return 1
	case "slow":
		time.Sleep(time.Second)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"claims": map[string]any{"sub": in.SubjectToken, "aud": in.Audience}})
	return 0
}

const k8sIssuer = "https://k8s.example"

type tokenFixture struct {
	iss       *Issuer
	srv       *httptest.Server
	ecKey     *ecdsa.PrivateKey
	rsaKey    *rsa.PrivateKey
	strangerK *ecdsa.PrivateKey
	upstream  *ecdsa.PrivateKey
	now       time.Time
}

func publicPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func yamlString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	f := &tokenFixture{now: time.Now()}
	var err error
	for _, k := range []**ecdsa.PrivateKey{&f.ecKey, &f.strangerK, &f.upstream} {
		if *k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	if f.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := keyset.Add(dir, keyset.ES256, f.now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	set, err := keyset.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(nil)
	f.srv.Start()
	t.Cleanup(f.srv.Close)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	upstreamJWKS, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.upstream.PublicKey, KeyID: "u1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	doc := `
origins:
  vms:
    provider: keys
    members:
      billing: { keys: [` + yamlString(publicPEM(t, &f.ecKey.PublicKey)) + `] }
      legacy: { keys: [` + yamlString(publicPEM(t, &f.strangerK.PublicKey)) + `, ` + yamlString(publicPEM(t, &f.rsaKey.PublicKey)) + `] }
  narrow:
    provider: keys
    audiences: [orders, ` + f.srv.URL + `/manage]
    members:
      narrow: { keys: [` + yamlString(publicPEM(t, &f.ecKey.PublicKey)) + `] }
  kube:
    provider: cluster
  kube-staging:
    provider: cluster
  aws:
    provider: verify
  unreachable:
    provider: elsewhere
providers:
  cluster:
    proof: { jwt: { issuer: ` + k8sIssuer + `, jwks: ` + string(upstreamJWKS) + `, shared: false, max_token_lifetime: 1h } }
    deny: { kubernetes.io/namespace: [kube-system] }
    name: ns/{kubernetes.io/namespace}
  elsewhere:
    proof: { jwt: { issuer: https://elsewhere.example, jwks_uri: "https://127.0.0.1:1/keys", shared: false } }
    name: "{sub}"
  verify:
    proof: { exec: { command: [` + yamlString(exe) + `, verifier], shared: false } }
    name: "{sub}"
`
	st, err := state.ParseState([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	s := state.DefaultSettings(f.srv.URL, td)
	s.Verifiers = [][]string{{exe, "verifier"}}
	p := policy.New(policy.Options{Settings: s})
	if err := p.Apply(&store.Snapshot{Version: "v1", State: st}); err != nil {
		t.Fatal(err)
	}
	runner, err := verifier.NewRunner(verifier.Limits{PerOrigin: 1, Total: 4, PerAddressPerMinute: 6000, PerAddressBurst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	f.iss, err = New(Config{
		URL:         f.srv.URL,
		TrustDomain: td,
		Keys:        staticKeys{set: set, seq: 1},
		Policy:      p,
		Verifiers:   runner,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:         func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.Config.Handler = f.iss.Handler()
	return f
}

func (f *tokenFixture) claims(clientID string) jwt.Claims {
	return jwt.Claims{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: jwt.Audience{f.iss.URL()},
		IssuedAt: jwt.NewNumericDate(f.now),
		Expiry:   jwt.NewNumericDate(f.now.Add(time.Minute)),
		ID:       rand.Text(),
	}
}

func sign(t *testing.T, key any, alg jose.SignatureAlgorithm, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *tokenFixture) form(clientID, assertion string, audiences ...string) url.Values {
	v := url.Values{
		"grant_type":            {GrantClientCredentials},
		"client_assertion_type": {ClientAssertionJWT},
		"client_assertion":      {assertion},
		"audience":              audiences,
	}
	if clientID != "" {
		v.Set("client_id", clientID)
	}
	return v
}

type response struct {
	status int
	header http.Header
	body   map[string]any
}

func (f *tokenFixture) post(t *testing.T, form url.Values) response {
	t.Helper()
	resp, err := http.PostForm(f.iss.TokenEndpoint(), form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := response{status: resp.StatusCode, header: resp.Header}
	if err := json.NewDecoder(resp.Body).Decode(&out.body); err != nil {
		t.Fatal(err)
	}
	return out
}

func claimsOf(t *testing.T, token string) jwt.Claims {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestClientCredentials(t *testing.T) {
	f := newTokenFixture(t)
	cases := []struct {
		name     string
		clientID string
		sendID   bool
		key      any
		alg      jose.SignatureAlgorithm
	}{
		{"ES256 key", "vms/billing", true, f.ecKey, jose.ES256},
		{"RS256 key, second of two registered", "vms/legacy", true, f.rsaKey, jose.RS256},
		{"client_id taken from the assertion", "vms/billing", false, f.ecKey, jose.ES256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := ""
			if c.sendID {
				id = c.clientID
			}
			resp := f.post(t, f.form(id, sign(t, c.key, c.alg, f.claims(c.clientID)), "orders", "payments", "orders"))
			if resp.status != http.StatusOK {
				t.Fatalf("status %d: %v", resp.status, resp.body)
			}
			if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			wantID := "spiffe://example.org/" + c.clientID
			if resp.body["spiffe_id"] != wantID || resp.body["token_type"] != "Bearer" ||
				resp.body["issued_token_type"] != TokenTypeJWT || resp.body["expires_in"] != float64(300) {
				t.Errorf("response = %v", resp.body)
			}
			claims := claimsOf(t, resp.body["access_token"].(string))
			if claims.Subject != wantID {
				t.Errorf("sub = %s, want %s", claims.Subject, wantID)
			}
			if len(claims.Audience) != 2 || claims.Audience[0] != "orders" || claims.Audience[1] != "payments" {
				t.Errorf("aud = %v, want [orders payments]", claims.Audience)
			}
		})
	}
}

func TestClientAuthenticationFailures(t *testing.T) {
	f := newTokenFixture(t)
	mutate := func(m func(*jwt.Claims)) jwt.Claims {
		c := f.claims("vms/billing")
		m(&c)
		return c
	}
	hs256 := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		body, _ := json.Marshal(f.claims("vms/billing"))
		payload := base64.RawURLEncoding.EncodeToString(body)
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write([]byte(header + "." + payload))
		return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	cases := map[string]struct {
		clientID  string
		assertion string
	}{
		"unknown member":         {"vms/nobody", sign(t, f.ecKey, jose.ES256, f.claims("vms/nobody"))},
		"unknown origin":         {"nope/billing", sign(t, f.ecKey, jose.ES256, f.claims("nope/billing"))},
		"origin of another kind": {"kube/billing", sign(t, f.ecKey, jose.ES256, f.claims("kube/billing"))},
		"member name alone":      {"billing", sign(t, f.ecKey, jose.ES256, f.claims("billing"))},
		"key not registered":     {"vms/billing", sign(t, f.strangerK, jose.ES256, f.claims("vms/billing"))},
		"another client's id":    {"vms/legacy", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing"))},
		"iss differs from sub":   {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Subject = "vms/legacy" }))},
		"wrong audience":         {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://elsewhere"} }))},
		"token endpoint as aud":  {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{f.iss.TokenEndpoint()} }))},
		"extra audience":         {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{f.iss.URL(), "https://elsewhere"} }))},
		"long-lived via future iat": {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(f.now.Add(365 * 24 * time.Hour))
			c.Expiry = jwt.NewNumericDate(f.now.Add(365*24*time.Hour + time.Minute))
		}))},
		"expired":              {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(f.now.Add(-time.Minute)) }))},
		"no exp":               {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = nil }))},
		"lifetime too long":    {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(f.now.Add(10 * time.Minute)) }))},
		"too long without iat": {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.IssuedAt = nil; c.Expiry = jwt.NewNumericDate(f.now.Add(10 * time.Minute)) }))},
		"issued in the future": {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(f.now.Add(time.Hour)) }))},
		"not yet valid":        {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(f.now.Add(time.Hour)) }))},
		"no jti":               {"vms/billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.ID = "" }))},
		"HMAC signature":       {"vms/billing", hs256()},
		"not a JWT":            {"vms/billing", "not-a-jwt"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, f.form(c.clientID, c.assertion, "orders"))
			if resp.status != http.StatusUnauthorized || resp.body["error"] != "invalid_client" ||
				resp.body["error_description"] != "client authentication failed" {
				t.Errorf("status %d, body %v; want 401 with the generic invalid_client body", resp.status, resp.body)
			}
		})
	}
}

func TestClientAssertionReplay(t *testing.T) {
	f := newTokenFixture(t)
	assertion := sign(t, f.ecKey, jose.ES256, f.claims("vms/billing"))
	if resp := f.post(t, f.form("vms/billing", assertion, "orders")); resp.status != http.StatusOK {
		t.Fatalf("first use: status %d: %v", resp.status, resp.body)
	}
	if resp := f.post(t, f.form("vms/billing", assertion, "orders")); resp.status != http.StatusUnauthorized {
		t.Fatalf("replay: status %d, want 401", resp.status)
	}
}

func TestTokenRequestValidation(t *testing.T) {
	f := newTokenFixture(t)
	good := func() url.Values {
		return f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders")
	}
	withAudiences := func(auds ...string) url.Values {
		v := good()
		v["audience"] = auds
		return v
	}
	narrow := func(auds ...string) url.Values {
		return f.form("narrow/narrow", sign(t, f.ecKey, jose.ES256, f.claims("narrow/narrow")), auds...)
	}

	cases := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"no audience", func() url.Values { v := good(); v.Del("audience"); return v }(), 400, "invalid_request"},
		{"empty audience", withAudiences(""), 400, "invalid_request"},
		{"too many audiences", withAudiences("a", "b", "c", "d", "e", "f"), 400, "invalid_request"},
		{"audience the origin does not allow", narrow("orders", "payments"), 400, "invalid_target"},
		{"issuer as audience", withAudiences(f.iss.URL()), 400, "invalid_target"},
		{"token endpoint as audience", withAudiences(f.iss.TokenEndpoint()), 400, "invalid_target"},
		{"management endpoint with another audience", withAudiences(f.iss.ManagementEndpoint(), "orders"), 400, "invalid_target"},
		{"actor token", func() url.Values { v := good(); v.Set("actor_token", "x"); return v }(), 400, "invalid_request"},
		{"no grant type", func() url.Values { v := good(); v.Del("grant_type"); return v }(), 400, "invalid_request"},
		{"unknown grant type", func() url.Values { v := good(); v.Set("grant_type", "password"); return v }(), 400, "unsupported_grant_type"},
		{"repeated grant type", func() url.Values { v := good(); v.Add("grant_type", GrantClientCredentials); return v }(), 400, "invalid_request"},
		{"wrong assertion type", func() url.Values { v := good(); v.Set("client_assertion_type", "x"); return v }(), 400, "invalid_request"},
		{"no assertion", func() url.Values { v := good(); v.Del("client_assertion"); return v }(), 400, "invalid_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := f.post(t, c.form)
			if resp.status != c.status || resp.body["error"] != c.code {
				t.Errorf("status %d, body %v; want %d %s", resp.status, resp.body, c.status, c.code)
			}
		})
	}

	t.Run("allowed audience", func(t *testing.T) {
		if resp := f.post(t, narrow("orders")); resp.status != http.StatusOK {
			t.Errorf("status %d: %v", resp.status, resp.body)
		}
	})
	// scope and resource are ignored, and resource, like audience, may
	// repeat (SPEC section 3).
	t.Run("scope and resource ignored", func(t *testing.T) {
		v := good()
		v.Set("scope", "openid admin")
		v.Add("resource", "https://api.example.org")
		v.Add("resource", "https://other.example.org")
		resp := f.post(t, v)
		if resp.status != http.StatusOK {
			t.Fatalf("status %d: %v", resp.status, resp.body)
		}
		if aud := claimsOf(t, resp.body["access_token"].(string)).Audience; len(aud) != 1 || aud[0] != "orders" {
			t.Errorf("aud = %v, want only the requested audience", aud)
		}
	})
	t.Run("repeated scope", func(t *testing.T) {
		v := good()
		v.Add("scope", "a")
		v.Add("scope", "b")
		if resp := f.post(t, v); resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
			t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
		}
	})
	t.Run("JSON body", func(t *testing.T) {
		resp, err := http.Post(f.iss.TokenEndpoint(), "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400", resp.StatusCode)
		}
	})
}

// A token for the management endpoint is allowed on its own, where the
// origin allows it, and lives at most five minutes.
func TestManagementAudience(t *testing.T) {
	f := newTokenFixture(t)
	f.iss.cfg.TokenTTL = time.Hour
	resp := f.post(t, f.form("narrow/narrow", sign(t, f.ecKey, jose.ES256, f.claims("narrow/narrow")), f.iss.ManagementEndpoint()))
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}
	claims := claimsOf(t, resp.body["access_token"].(string))
	if d := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); d != 5*time.Minute {
		t.Errorf("a management token lives %s, want 5m", d)
	}
	resp = f.post(t, f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders"))
	if claims := claimsOf(t, resp.body["access_token"].(string)); claims.Expiry.Time().Sub(claims.IssuedAt.Time()) != time.Hour {
		t.Error("an ordinary token did not get the configured lifetime")
	}
}

func TestDiscoveryAdvertisesBothGrants(t *testing.T) {
	f := newTokenFixture(t)
	var doc map[string]any
	resp, err := http.Get(f.iss.URL() + DiscoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(doc["grant_types_supported"]); got != "["+GrantClientCredentials+" "+GrantTokenExchange+"]" {
		t.Errorf("grant_types_supported = %s", got)
	}
	if got := fmt.Sprint(doc["token_endpoint_auth_methods_supported"]); got != "[private_key_jwt none]" {
		t.Errorf("token_endpoint_auth_methods_supported = %s", got)
	}
}

// Audience policy is checked after authentication, so a refused audience
// still consumes the assertion.
func TestRefusedAudienceConsumesAssertion(t *testing.T) {
	f := newTokenFixture(t)
	assertion := sign(t, f.ecKey, jose.ES256, f.claims("narrow/narrow"))
	if resp := f.post(t, f.form("narrow/narrow", assertion, "payments")); resp.body["error"] != "invalid_target" {
		t.Fatalf("first request: %v, want invalid_target", resp.body)
	}
	if resp := f.post(t, f.form("narrow/narrow", assertion, "orders")); resp.status != http.StatusUnauthorized {
		t.Fatalf("reusing the assertion: status %d, want 401", resp.status)
	}
}

func TestOversizedBody(t *testing.T) {
	f := newTokenFixture(t)
	form := f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders")
	form.Set("padding", strings.Repeat("x", 70<<10))
	if resp := f.post(t, form); resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
		t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
	}
}

// Parameters are read from the body only; a query string carries no weight.
func TestQueryParametersIgnored(t *testing.T) {
	f := newTokenFixture(t)
	form := f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")))
	resp, err := http.Post(f.iss.TokenEndpoint()+"?audience=orders", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("body %v; want invalid_request for the missing audience", body)
	}
}

func TestReplayCache(t *testing.T) {
	c := newReplayCache()
	now := time.Now()
	exp := now.Add(time.Minute)
	if !c.use("a", "1", exp, now) || c.use("a", "1", exp, now) {
		t.Fatal("a jti must be accepted once")
	}
	if !c.use("b", "1", exp, now) {
		t.Fatal("the same jti from another client was refused")
	}
	if !c.use("a", "1", exp, exp.Add(2*sweepInterval)) {
		t.Fatal("an expired entry still blocks its jti")
	}

	for i := range maxReplayEntriesPerClient {
		c.use("greedy", fmt.Sprint(i), exp, now)
	}
	if c.use("greedy", "one-more", exp, now) {
		t.Error("a client over its cap was accepted")
	}
	if !c.use("modest", "1", exp, now) {
		t.Error("one client's full cache locked out another client")
	}
}

// serviceAccountToken signs a token as the upstream would, for the given
// audiences.
func (f *tokenFixture) serviceAccountToken(t *testing.T, namespace string, lifetime time.Duration, audiences ...string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: f.upstream, KeyID: "u1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": k8sIssuer, "aud": audiences, "sub": "system:serviceaccount:" + namespace + ":billing",
		"iat": f.now.Unix(), "exp": f.now.Add(lifetime).Unix(),
		"kubernetes.io": map[string]any{"namespace": namespace},
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func exchangeForm(token, tokenType string, mutate ...func(url.Values)) url.Values {
	v := url.Values{
		"grant_type":         {GrantTokenExchange},
		"subject_token":      {token},
		"subject_token_type": {tokenType},
		"audience":           {"orders"},
	}
	for _, m := range mutate {
		m(v)
	}
	return v
}

func TestTokenExchangeJWT(t *testing.T) {
	f := newTokenFixture(t)
	kube := f.iss.URL() + "/origins/kube"
	good := f.serviceAccountToken(t, "shop", time.Hour, kube)

	resp := f.post(t, exchangeForm(good, TokenTypeJWT))
	if resp.status != http.StatusOK || resp.body["spiffe_id"] != "spiffe://example.org/kube/ns/shop" {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}
	if resp := f.post(t, exchangeForm(good, TokenTypeIDToken)); resp.status != http.StatusOK {
		t.Errorf("id_token type: status %d: %v", resp.status, resp.body)
	}
	staging := f.post(t, exchangeForm(f.serviceAccountToken(t, "shop", time.Hour, "other", f.iss.URL()+"/origins/kube-staging"), TokenTypeJWT))
	if staging.body["spiffe_id"] != "spiffe://example.org/kube-staging/ns/shop" {
		t.Errorf("the second origin of the same upstream: %v", staging.body)
	}

	rejected := []struct {
		name string
		form url.Values
	}{
		{"no origin takes the audience", exchangeForm(f.serviceAccountToken(t, "shop", time.Hour, "spiffex"), TokenTypeJWT)},
		{"two origins reached", exchangeForm(f.serviceAccountToken(t, "shop", time.Hour, kube, f.iss.URL()+"/origins/kube-staging"), TokenTypeJWT)},
		{"the origin does not admit it", exchangeForm(f.serviceAccountToken(t, "kube-system", time.Hour, kube), TokenTypeJWT)},
		{"meant to live too long", exchangeForm(f.serviceAccountToken(t, "shop", 2*time.Hour, kube), TokenTypeJWT)},
		{"expired", exchangeForm(f.serviceAccountToken(t, "shop", -time.Hour, kube), TokenTypeJWT)},
		{"signed by a stranger", exchangeForm(sign(t, f.strangerK, jose.ES256, map[string]any{"iss": k8sIssuer, "aud": kube, "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), "kubernetes.io": map[string]any{"namespace": "shop"}}), TokenTypeJWT)},
		{"the issuer's own token", exchangeForm(sign(t, f.ecKey, jose.ES256, map[string]any{"iss": f.iss.URL(), "aud": kube}), TokenTypeJWT)},
		{"not a JWT", exchangeForm("opaque", TokenTypeJWT)},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			resp := f.post(t, c.form)
			if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" || resp.body["error_description"] != "subject token rejected" {
				t.Errorf("status %d, body %v; want the one answer to every refused subject token", resp.status, resp.body)
			}
		})
	}

	others := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"keys cannot be fetched", exchangeForm(sign(t, f.upstream, jose.ES256, map[string]any{"iss": "https://elsewhere.example", "aud": f.iss.URL() + "/origins/unreachable"}), TokenTypeJWT), 500, "server_error"},
		{"missing token", exchangeForm("", TokenTypeJWT), 400, "invalid_request"},
		{"token too large", exchangeForm(strings.Repeat("a", maxSubjectToken+1), TokenTypeJWT), 400, "invalid_request"},
		{"origin with a JWT", exchangeForm(good, TokenTypeJWT, func(v url.Values) { v.Set("origin", "kube") }), 400, "invalid_request"},
		{"other token type", exchangeForm(good, "urn:ietf:params:oauth:token-type:access_token"), 400, "invalid_request"},
		{"other requested type", exchangeForm(good, TokenTypeJWT, func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token") }), 400, "invalid_request"},
		{"issuer as audience", exchangeForm(good, TokenTypeJWT, func(v url.Values) { v.Set("audience", f.iss.URL()) }), 400, "invalid_target"},
	}
	for _, c := range others {
		t.Run(c.name, func(t *testing.T) {
			resp := f.post(t, c.form)
			if resp.status != c.status || resp.body["error"] != c.code {
				t.Errorf("status %d, body %v; want %d %s", resp.status, resp.body, c.status, c.code)
			}
		})
	}
}

func TestTokenExchangeExec(t *testing.T) {
	f := newTokenFixture(t)
	exec := func(proof string, mutate ...func(url.Values)) url.Values {
		return exchangeForm(proof, TokenTypeExec, append([]func(url.Values){func(v url.Values) { v.Set("origin", "aws") }}, mutate...)...)
	}
	resp := f.post(t, exec("i-0abc"))
	if resp.status != http.StatusOK || resp.body["spiffe_id"] != "spiffe://example.org/aws/i-0abc" {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}

	for name, form := range map[string]url.Values{
		"the verifier refuses":   exec("fail"),
		"no exec origin by name": exec("i-0abc", func(v url.Values) { v.Set("origin", "nope") }),
		"a jwt origin by name":   exec("i-0abc", func(v url.Values) { v.Set("origin", "kube") }),
		"not UTF-8":              exec("\xff"),
		"not a segment":          exec("a/b"),
	} {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, form)
			if resp.status != http.StatusBadRequest || resp.body["error_description"] != "subject token rejected" {
				t.Errorf("status %d, body %v; want the one answer to every refused subject token", resp.status, resp.body)
			}
		})
	}
	if resp := f.post(t, exchangeForm("i-0abc", TokenTypeExec)); resp.body["error"] != "invalid_request" {
		t.Errorf("without origin: %v", resp.body)
	}

	// The fixture lets one verifier run per origin: a second request while
	// the first runs is turned away.
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- f.post(t, exec("slow")).status
		}()
	}
	wg.Wait()
	close(statuses)
	got := map[int]int{}
	for s := range statuses {
		got[s]++
	}
	if got[http.StatusOK] != 1 || got[http.StatusInternalServerError] != 1 {
		t.Errorf("statuses %v; want one 200 and one 500 for the request over the bound", got)
	}
}

func TestKeysFor(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := []crypto.PublicKey{&ec.PublicKey, &rs.PublicKey}
	if got := keysFor("ES256", keys); len(got) != 1 || got[0] != &ec.PublicKey {
		t.Errorf("ES256: %v", got)
	}
	if got := keysFor("RS256", keys[:1]); len(got) != 0 {
		t.Errorf("RS256 with only an EC key: %v; the decoy must be used", got)
	}
}

func TestClientAddress(t *testing.T) {
	iss := &Issuer{cfg: Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	cases := []struct {
		peer string
		xff  []string
		want string
	}{
		{"192.0.2.1:5000", []string{"198.51.100.7"}, "192.0.2.1"},
		{"10.0.0.2:5000", nil, "10.0.0.2"},
		{"10.0.0.2:5000", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		{"10.0.0.2:5000", []string{"203.0.113.9", "198.51.100.7, 10.1.1.1"}, "198.51.100.7"},
		{"10.0.0.2:5000", []string{"10.3.3.3, 10.1.1.1"}, "10.3.3.3"},
		{"10.0.0.2:5000", []string{"198.51.100.7, garbage, 10.1.1.1"}, "10.1.1.1"},
		{"[::ffff:10.0.0.2]:5000", []string{"2001:db8::1"}, "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/token", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := iss.clientAddress(r).String(); got != c.want {
			t.Errorf("peer %s, X-Forwarded-For %q: %s, want %s", c.peer, c.xff, got, c.want)
		}
	}
}

// Behind a trusted proxy, the per-address verifier limit applies to the
// client X-Forwarded-For names, not to the proxy.
func TestVerifierLimitPerForwardedClient(t *testing.T) {
	f := newTokenFixture(t)
	runner, err := verifier.NewRunner(verifier.Limits{PerOrigin: 4, Total: 4, PerAddressPerMinute: 1, PerAddressBurst: 2})
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.iss.cfg
	cfg.Verifiers = runner
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	if f.iss, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	f.srv.Config.Handler = f.iss.Handler()

	post := func(client string) int {
		t.Helper()
		form := exchangeForm("i-0abc", TokenTypeExec, func(v url.Values) { v.Set("origin", "aws") })
		req, err := http.NewRequest(http.MethodPost, f.iss.TokenEndpoint(), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", client)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := range 2 {
		if s := post("198.51.100.7"); s != http.StatusOK {
			t.Fatalf("request %d within the burst: status %d", i, s)
		}
	}
	if s := post("198.51.100.7"); s != http.StatusInternalServerError {
		t.Errorf("a request over the client's limit: status %d, want 500", s)
	}
	if s := post("198.51.100.8"); s != http.StatusOK {
		t.Errorf("another client behind the same proxy: status %d, want 200", s)
	}
}

// An exposed key stays published but never signs: the newest key that is not
// exposed does, and with every key exposed the token endpoint refuses with
// server_error rather than sign.
func TestExposedKeysNeverSign(t *testing.T) {
	f := newTokenFixture(t)
	dir := t.TempDir()
	older, err := keyset.Add(dir, keyset.ES256, f.now.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newer, err := keyset.Add(dir, keyset.ES256, f.now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := keyset.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	use := func(exposed ...string) {
		keys := loaded.Keys()
		for i := range keys {
			keys[i].Exposed = slices.Contains(exposed, keys[i].ID)
		}
		set, err := keyset.NewSet(keys)
		if err != nil {
			t.Fatal(err)
		}
		f.iss.cfg.Keys = staticKeys{set: set, seq: 2}
	}
	request := func() response {
		return f.post(t, f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders"))
	}
	kid := func(token string) string {
		parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Headers[0].KeyID
	}

	use(newer.ID)
	resp := request()
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}
	if got := kid(resp.body["access_token"].(string)); got != older.ID {
		t.Errorf("signed with %s, want the older key, as the newer one is exposed", got)
	}
	jwks, err := http.Get(f.iss.URL() + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(jwks.Body)
	jwks.Body.Close()
	if !strings.Contains(string(body), newer.ID) {
		t.Error("the exposed key is no longer published")
	}

	use(older.ID, newer.ID)
	resp = request()
	if resp.status != http.StatusInternalServerError || resp.body["error"] != "server_error" {
		t.Errorf("with every key exposed: status %d, body %v; want 500 server_error", resp.status, resp.body)
	}
}
