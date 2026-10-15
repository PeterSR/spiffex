package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/keyset"
)

type clientMap map[string]Client

func (m clientMap) Client(id string) (Client, bool) {
	c, ok := m[id]
	return c, ok
}

type tokenFixture struct {
	iss       *Issuer
	srv       *httptest.Server
	ecKey     *ecdsa.PrivateKey
	rsaKey    *rsa.PrivateKey
	strangerK *ecdsa.PrivateKey
	now       time.Time
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	f := &tokenFixture{now: time.Now()}
	var err error
	if f.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if f.strangerK, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
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
	f.iss, err = New(Config{
		URL:         f.srv.URL,
		TrustDomain: td,
		Keys:        staticKeys{set: set, seq: 1},
		Clients: clientMap{
			"billing": {ID: "billing", SPIFFEID: spiffeid.RequireFromPath(td, "/billing"), PublicKeys: []crypto.PublicKey{&f.ecKey.PublicKey}},
			"legacy":  {ID: "legacy", SPIFFEID: spiffeid.RequireFromPath(td, "/legacy"), PublicKeys: []crypto.PublicKey{&f.strangerK.PublicKey, &f.rsaKey.PublicKey}},
			"narrow":  {ID: "narrow", SPIFFEID: spiffeid.RequireFromPath(td, "/narrow"), PublicKeys: []crypto.PublicKey{&f.ecKey.PublicKey}, Audiences: []string{"orders"}},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return f.now },
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

func TestClientCredentials(t *testing.T) {
	f := newTokenFixture(t)

	cases := []struct {
		name     string
		clientID string
		sendID   bool
		key      any
		alg      jose.SignatureAlgorithm
	}{
		{"ES256 key", "billing", true, f.ecKey, jose.ES256},
		{"RS256 key, second of two registered", "legacy", true, f.rsaKey, jose.RS256},
		{"client_id taken from the assertion", "billing", false, f.ecKey, jose.ES256},
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
			token, err := jwt.ParseSigned(resp.body["access_token"].(string), []jose.SignatureAlgorithm{jose.ES256})
			if err != nil {
				t.Fatal(err)
			}
			var claims jwt.Claims
			if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
				t.Fatal(err)
			}
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
		c := f.claims("billing")
		m(&c)
		return c
	}
	hs256 := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		body, _ := json.Marshal(f.claims("billing"))
		payload := base64.RawURLEncoding.EncodeToString(body)
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write([]byte(header + "." + payload))
		return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	cases := map[string]struct {
		clientID  string
		assertion string
	}{
		"unknown client":        {"nobody", sign(t, f.ecKey, jose.ES256, f.claims("nobody"))},
		"key not registered":    {"billing", sign(t, f.strangerK, jose.ES256, f.claims("billing"))},
		"another client's id":   {"legacy", sign(t, f.ecKey, jose.ES256, f.claims("billing"))},
		"iss differs from sub":  {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Subject = "legacy" }))},
		"wrong audience":        {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://elsewhere"} }))},
		"token endpoint as aud": {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{f.iss.TokenEndpoint()} }))},
		"extra audience":        {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Audience = jwt.Audience{f.iss.URL(), "https://elsewhere"} }))},
		"long-lived via future iat": {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(f.now.Add(365 * 24 * time.Hour))
			c.Expiry = jwt.NewNumericDate(f.now.Add(365*24*time.Hour + time.Minute))
		}))},
		"expired":              {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(f.now.Add(-time.Minute)) }))},
		"no exp":               {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = nil }))},
		"lifetime too long":    {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(f.now.Add(10 * time.Minute)) }))},
		"too long without iat": {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.IssuedAt = nil; c.Expiry = jwt.NewNumericDate(f.now.Add(10 * time.Minute)) }))},
		"issued in the future": {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(f.now.Add(time.Hour)) }))},
		"not yet valid":        {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(f.now.Add(time.Hour)) }))},
		"no jti":               {"billing", sign(t, f.ecKey, jose.ES256, mutate(func(c *jwt.Claims) { c.ID = "" }))},
		"HMAC signature":       {"billing", hs256()},
		"not a JWT":            {"billing", "not-a-jwt"},
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
	assertion := sign(t, f.ecKey, jose.ES256, f.claims("billing"))
	if resp := f.post(t, f.form("billing", assertion, "orders")); resp.status != http.StatusOK {
		t.Fatalf("first use: status %d: %v", resp.status, resp.body)
	}
	if resp := f.post(t, f.form("billing", assertion, "orders")); resp.status != http.StatusUnauthorized {
		t.Fatalf("replay: status %d, want 401", resp.status)
	}
}

func TestTokenRequestValidation(t *testing.T) {
	f := newTokenFixture(t)
	good := func() url.Values {
		return f.form("billing", sign(t, f.ecKey, jose.ES256, f.claims("billing")), "orders")
	}
	manyAudiences := good()
	manyAudiences["audience"] = strings.Split("a b c d e f", " ")

	cases := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"no audience", func() url.Values { v := good(); v.Del("audience"); return v }(), 400, "invalid_request"},
		{"empty audience", func() url.Values { v := good(); v.Set("audience", ""); return v }(), 400, "invalid_request"},
		{"too many audiences", manyAudiences, 400, "invalid_request"},
		{"audience outside the allowlist", f.form("narrow", sign(t, f.ecKey, jose.ES256, f.claims("narrow")), "orders", "payments"), 400, "invalid_target"},
		{"issuer as audience", func() url.Values { v := good(); v.Set("audience", f.iss.URL()); return v }(), 400, "invalid_target"},
		{"token endpoint as audience", func() url.Values { v := good(); v.Set("audience", f.iss.TokenEndpoint()); return v }(), 400, "invalid_target"},
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
		resp := f.post(t, f.form("narrow", sign(t, f.ecKey, jose.ES256, f.claims("narrow")), "orders"))
		if resp.status != http.StatusOK {
			t.Errorf("status %d: %v", resp.status, resp.body)
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

func TestDiscoveryAdvertisesClientCredentials(t *testing.T) {
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
	grants, _ := doc["grant_types_supported"].([]any)
	if len(grants) != 1 || grants[0] != GrantClientCredentials {
		t.Errorf("grant_types_supported = %v", grants)
	}
	methods, _ := doc["token_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "private_key_jwt" {
		t.Errorf("token_endpoint_auth_methods_supported = %v", methods)
	}
}

// Audience policy is checked after authentication, so a refused audience
// still consumes the assertion.
func TestRefusedAudienceConsumesAssertion(t *testing.T) {
	f := newTokenFixture(t)
	assertion := sign(t, f.ecKey, jose.ES256, f.claims("narrow"))
	if resp := f.post(t, f.form("narrow", assertion, "payments")); resp.body["error"] != "invalid_target" {
		t.Fatalf("first request: %v, want invalid_target", resp.body)
	}
	if resp := f.post(t, f.form("narrow", assertion, "orders")); resp.status != http.StatusUnauthorized {
		t.Fatalf("reusing the assertion: status %d, want 401", resp.status)
	}
}

func TestOversizedBody(t *testing.T) {
	f := newTokenFixture(t)
	form := f.form("billing", sign(t, f.ecKey, jose.ES256, f.claims("billing")), "orders")
	form.Set("padding", strings.Repeat("x", 70<<10))
	if resp := f.post(t, form); resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
		t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
	}
}

// Parameters are read from the body only; a query string carries no weight.
func TestQueryParametersIgnored(t *testing.T) {
	f := newTokenFixture(t)
	form := f.form("billing", sign(t, f.ecKey, jose.ES256, f.claims("billing")))
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

type fakeExchanger map[string]error

func (f fakeExchanger) Exchange(_ context.Context, token string) (spiffeid.ID, error) {
	if err, ok := f[token]; ok {
		return spiffeid.ID{}, err
	}
	return spiffeid.RequireFromPath(td, "/ns/shop/sa/"+token), nil
}

func TestTokenExchange(t *testing.T) {
	f := newTokenFixture(t)
	f.iss.cfg.Exchanger = fakeExchanger{
		"forged": fmt.Errorf("%w: bad signature", exchange.ErrRejected),
		"broken": errors.New("upstream keys unavailable"),
	}
	form := func(token string, mutate ...func(url.Values)) url.Values {
		v := url.Values{
			"grant_type":         {GrantTokenExchange},
			"subject_token":      {token},
			"subject_token_type": {TokenTypeJWT},
			"audience":           {"orders"},
		}
		for _, m := range mutate {
			m(v)
		}
		return v
	}

	resp := f.post(t, form("billing"))
	if resp.status != http.StatusOK || resp.body["spiffe_id"] != "spiffe://example.org/ns/shop/sa/billing" {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}
	if resp := f.post(t, form("billing", func(v url.Values) { v.Set("subject_token_type", TokenTypeIDToken) })); resp.status != http.StatusOK {
		t.Errorf("id_token type: status %d: %v", resp.status, resp.body)
	}

	cases := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"rejected token", form("forged"), 400, "invalid_request"},
		{"exchanger failure", form("broken"), 500, "server_error"},
		{"missing token", form(""), 400, "invalid_request"},
		{"other token type", form("billing", func(v url.Values) { v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token") }), 400, "invalid_request"},
		{"other requested type", form("billing", func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token") }), 400, "invalid_request"},
		{"issuer as audience", form("billing", func(v url.Values) { v.Set("audience", f.iss.URL()) }), 400, "invalid_target"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := f.post(t, c.form)
			if resp.status != c.status || resp.body["error"] != c.code {
				t.Errorf("status %d, body %v; want %d %s", resp.status, resp.body, c.status, c.code)
			}
			if c.code == "invalid_request" && strings.Contains(fmt.Sprint(resp.body["error_description"]), "signature") {
				t.Error("the rejection reason leaked to the caller")
			}
		})
	}

	f.iss.cfg.Exchanger = nil
	if resp := f.post(t, form("billing")); resp.body["error"] != "unsupported_grant_type" {
		t.Errorf("without an exchanger: %v", resp.body)
	}
}
