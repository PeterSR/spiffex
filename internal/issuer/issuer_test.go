package issuer

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

var emptyPolicy = policy.New(policy.Options{Settings: state.DefaultSettings("https://issuer.example.org", td)})

type staticKeys struct {
	set *keyset.Set
	seq uint64
}

func (s staticKeys) Current() (*keyset.Set, uint64, <-chan struct{}) { return s.set, s.seq, nil }

// testIssuer starts an issuer behind a TLS test server. path is appended to
// the server URL to form the issuer URL.
func testIssuer(t *testing.T, path string, algs ...keyset.Algorithm) (*Issuer, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	created := time.Now().Add(-48 * time.Hour)
	for i, alg := range algs {
		if _, err := keyset.Add(dir, alg, created.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	set, err := keyset.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	iss, err := New(Config{
		URL:         srv.URL + path,
		TrustDomain: td,
		Keys:        staticKeys{set: set, seq: 7},
		Policy:      emptyPolicy,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = iss.Handler()
	return iss, srv
}

func TestDiscovery(t *testing.T) {
	for _, path := range []string{"", "/customers/acme"} {
		t.Run("path="+path, func(t *testing.T) {
			iss, srv := testIssuer(t, path, keyset.ES256)
			var doc map[string]any
			getJSON(t, srv, iss.URL()+DiscoveryPath, &doc)
			want := map[string]string{
				"issuer":                 iss.URL(),
				"jwks_uri":               iss.URL() + JWKSPath,
				"token_endpoint":         iss.URL() + TokenPath,
				"spiffe_bundle_endpoint": iss.URL() + BundlePath,
				"spiffe_trust_domain":    "example.org",
			}
			for field, value := range want {
				if doc[field] != value {
					t.Errorf("%s = %v, want %s", field, doc[field], value)
				}
			}
			algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
			if len(algs) != 1 || algs[0] != "ES256" {
				t.Errorf("id_token_signing_alg_values_supported = %v, want [ES256]", algs)
			}
		})
	}
}

// A token verifies through go-spiffe against the bundle endpoint, the way a
// federating SPIFFE verifier would consume it.
func TestMintVerifiesAgainstSPIFFEBundle(t *testing.T) {
	for _, alg := range []keyset.Algorithm{keyset.ES256, keyset.RS256} {
		t.Run(string(alg), func(t *testing.T) {
			iss, srv := testIssuer(t, "", alg)
			id := spiffeid.RequireFromPath(td, "/billing")
			token, _, err := iss.Mint(id, []string{"orders"})
			if err != nil {
				t.Fatal(err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			bundle, err := federation.FetchBundle(context.Background(), td, iss.URL()+BundlePath, federation.WithWebPKIRoots(roots))
			if err != nil {
				t.Fatal(err)
			}
			if seq, ok := bundle.SequenceNumber(); !ok || seq != 7 {
				t.Errorf("sequence number = %d (%v), want 7", seq, ok)
			}
			if hint, ok := bundle.RefreshHint(); !ok || hint != DefaultActivationDelay/5 {
				t.Errorf("refresh hint = %s (%v), want %s", hint, ok, DefaultActivationDelay/5)
			}

			svid, err := jwtsvid.ParseAndValidate(token, bundle, []string{"orders"})
			if err != nil {
				t.Fatal(err)
			}
			if svid.ID != id {
				t.Errorf("SPIFFE ID = %s, want %s", svid.ID, id)
			}
			if _, err := jwtsvid.ParseAndValidate(token, bundle, []string{"payments"}); err == nil {
				t.Error("token validated for an audience it was not issued for")
			}
		})
	}
}

// A token verifies as a plain OIDC JWT against the JWKS, the way a cloud
// provider or API gateway would consume it.
func TestMintVerifiesAgainstJWKS(t *testing.T) {
	iss, srv := testIssuer(t, "", keyset.ES256, keyset.RS256)
	id := spiffeid.RequireFromPath(td, "/billing")
	token, expires, err := iss.Mint(id, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}

	var jwks jose.JSONWebKeySet
	getJSON(t, srv, iss.URL()+JWKSPath, &jwks)
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2", len(jwks.Keys))
	}
	for _, k := range jwks.Keys {
		if k.Use != "sig" || k.Algorithm == "" || k.KeyID == "" {
			t.Errorf("JWK %s: use=%q alg=%q, want use=sig and an alg", k.KeyID, k.Use, k.Algorithm)
		}
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if typ := parsed.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "JWT" {
		t.Errorf("typ = %v, want JWT", typ)
	}
	// Both keys are older than the activation delay, so the newer one signs.
	if parsed.Headers[0].Algorithm != "RS256" {
		t.Errorf("signed with %s, want the newer RS256 key", parsed.Headers[0].Algorithm)
	}
	var claims jwt.Claims
	if err := parsed.Claims(jwks, &claims); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: iss.URL(), Subject: id.String(), AnyAudience: jwt.Audience{"b"}}); err != nil {
		t.Fatal(err)
	}
	if !claims.Expiry.Time().Equal(expires) {
		t.Errorf("exp = %s, want %s", claims.Expiry.Time(), expires)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}
}

func TestMintRejectsForeignTrustDomain(t *testing.T) {
	iss, _ := testIssuer(t, "", keyset.ES256)
	other := spiffeid.RequireFromString("spiffe://other.org/billing")
	if _, _, err := iss.Mint(other, []string{"x"}); err == nil {
		t.Fatal("minted a token for another trust domain")
	}
}

func TestValidateURL(t *testing.T) {
	good := []string{"https://issuer.example.org", "https://example.org/spiffex", "http://127.0.0.1:8443"}
	bad := []string{"", "issuer.example.org", "ftp://example.org", "https://example.org/", "https://example.org?x=1",
		"https://example.org#f", "https://u:p@example.org", "https://example.org/{a}", "https://example.org/a/../b",
		"https://example.org/a b", "HTTPS://example.org", "http://issuer.example.org"}
	for _, u := range good {
		if _, err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want ok", u, err)
		}
	}
	for _, u := range bad {
		if _, err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) succeeded, want an error", u)
		}
	}
}

func getJSON(t *testing.T, srv *httptest.Server, url string, v any) {
	t.Helper()
	resp, err := srv.Client().Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestPathPrefix(t *testing.T) {
	iss, srv := testIssuer(t, "/customers/acme", keyset.ES256)
	metadata := srv.URL + OAuthMetadataPath + "/customers/acme"
	resp, err := srv.Client().Get(metadata)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: %s", metadata, resp.Status)
	}
	for _, p := range []string{JWKSPath, BundlePath, HealthPath} {
		resp, err := srv.Client().Get(iss.URL() + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s under the prefix: %s", p, resp.Status)
		}
		resp, err = srv.Client().Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s without the prefix: %s, want 404", p, resp.Status)
		}
	}
}

func TestCacheHeaders(t *testing.T) {
	iss, srv := testIssuer(t, "", keyset.ES256)
	want := fmt.Sprintf("public, max-age=%d", int((DefaultActivationDelay / 5).Seconds()))
	for _, p := range []string{DiscoveryPath, JWKSPath, BundlePath} {
		resp, err := srv.Client().Get(iss.URL() + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", p, got, want)
		}
	}
}

// The token carries exactly the header fields and claims SPEC section 4 lists.
func TestTokenShape(t *testing.T) {
	iss, _ := testIssuer(t, "", keyset.ES256)
	id := spiffeid.RequireFromPath(td, "/billing")
	decode := func(token string) (header, claims map[string]any) {
		parts := strings.Split(token, ".")
		for i, v := range []*map[string]any{&header, &claims} {
			raw, err := base64.RawURLEncoding.DecodeString(parts[i])
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, v); err != nil {
				t.Fatal(err)
			}
		}
		return header, claims
	}

	token, _, err := iss.Mint(id, []string{"orders"})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := decode(token)
	if len(header) != 3 || header["alg"] != "ES256" || header["typ"] != "JWT" || header["kid"] == "" {
		t.Errorf("header = %v", header)
	}
	if len(claims) != 6 || claims["aud"] != "orders" || claims["sub"] != id.String() || claims["iss"] != iss.URL() {
		t.Errorf("claims = %v", claims)
	}
	for _, c := range []string{"exp", "iat", "jti"} {
		if _, ok := claims[c]; !ok {
			t.Errorf("claim %s missing", c)
		}
	}

	token, _, err = iss.Mint(id, []string{"orders", "payments", "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if _, claims := decode(token); fmt.Sprint(claims["aud"]) != "[orders payments]" {
		t.Errorf("aud = %v, want [orders payments]", claims["aud"])
	}
}

func TestMintRejectsBadAudiences(t *testing.T) {
	iss, _ := testIssuer(t, "", keyset.ES256)
	id := spiffeid.RequireFromPath(td, "/billing")
	for _, auds := range [][]string{nil, {""}, {strings.Repeat("a", 513)}, {"a", "b", "c", "d", "e", "f"}, {iss.URL()}, {iss.TokenEndpoint()}, {iss.ManagementEndpoint(), "a"}} {
		if _, _, err := iss.Mint(id, auds); err == nil {
			t.Errorf("Mint(%q) succeeded, want an error", auds)
		}
	}
}

// A newly published key does not sign until the activation delay has passed.
func TestMintRotation(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	old, err := keyset.Add(dir, keyset.ES256, start)
	if err != nil {
		t.Fatal(err)
	}
	next, err := keyset.Add(dir, keyset.ES256, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	set, err := keyset.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(24*time.Hour + 29*time.Minute)
	iss, err := New(Config{
		URL: "https://issuer.example.org", TrustDomain: td, Keys: staticKeys{set: set}, Policy: emptyPolicy,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	kid := func() string {
		token, _, err := iss.Mint(spiffeid.RequireFromPath(td, "/x"), []string{"y"})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Headers[0].KeyID
	}
	if got := kid(); got != old.ID {
		t.Errorf("signed with %s before the new key's activation, want the old key", got)
	}
	now = now.Add(time.Minute)
	if got := kid(); got != next.ID {
		t.Errorf("signed with %s after activation, want the new key", got)
	}
}

func TestConfigValidation(t *testing.T) {
	set := func() *keyset.Set {
		dir := t.TempDir()
		if _, err := keyset.Add(dir, keyset.ES256, time.Now()); err != nil {
			t.Fatal(err)
		}
		s, err := keyset.LoadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()
	base := func() Config {
		return Config{URL: "https://issuer.example.org", TrustDomain: td, Keys: staticKeys{set: set}, Policy: emptyPolicy}
	}
	cases := map[string]func(*Config){
		"negative refresh hint":   func(c *Config) { c.RefreshHint = -5 * time.Second },
		"sub-second refresh hint": func(c *Config) { c.RefreshHint = 300 * time.Millisecond },
		"refresh hint too long":   func(c *Config) { c.RefreshHint = 11 * time.Minute },
		"activation delay tiny":   func(c *Config) { c.ActivationDelay = time.Second },
		"token TTL too short":     func(c *Config) { c.TokenTTL = time.Second },
		"token TTL over an hour":  func(c *Config) { c.TokenTTL = time.Hour + time.Second },
		"no policy":               func(c *Config) { c.Policy = nil },
		"no keys":                 func(c *Config) { c.Keys = nil },
		"no trust domain":         func(c *Config) { c.TrustDomain = spiffeid.TrustDomain{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}
