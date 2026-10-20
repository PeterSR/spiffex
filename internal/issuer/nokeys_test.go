package issuer

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// Removing the last JWT key stops JWT-SVIDs and nothing else: the token
// endpoint refuses them with invalid_request, as it refuses an X.509-SVID
// when no CA is left; discovery, the JWKS and the bundle stay up and publish
// no JWT key; X.509-SVIDs go on. A key that comes back signs again.
func TestRemovingTheLastJWTKeyStopsJWTSVIDsOnly(t *testing.T) {
	keysDir := t.TempDir()
	first, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := keyset.NewWatcher(keysDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	withAuthority := withCA(t, longValidity, nil)
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		withAuthority(f, cfg)
		cfg.Keys = watcher
	})
	jwtRequest := func() response {
		return f.post(t, f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders"))
	}
	if resp := jwtRequest(); resp.status != http.StatusOK {
		t.Fatalf("JWT-SVID before the removal: %d %v", resp.status, resp.body)
	}

	if err := os.Remove(filepath.Join(keysDir, first.File)); err != nil {
		t.Fatal(err)
	}
	if watcher.Reload() || !watcher.Reload() {
		t.Fatal("the removal was not noticed on the second poll")
	}

	resp := jwtRequest()
	if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" ||
		resp.body["error_description"] != "this issuer issues no JWT-SVIDs" {
		t.Errorf("JWT-SVID without a key: %d %v, want 400 invalid_request", resp.status, resp.body)
	}
	if resp.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", resp.header.Get("Cache-Control"))
	}
	// The same answer from the token exchange grant, and before the caller
	// is authenticated, as for the CA.
	token := f.serviceAccountToken(t, "shop", time.Hour, f.iss.URL()+"/origins/kube")
	if resp := f.post(t, exchangeForm(token, TokenTypeJWT)); resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
		t.Errorf("exchange without a key: %d %v", resp.status, resp.body)
	}
	bad := f.form("vms/billing", "not an assertion", "orders")
	if resp := f.post(t, bad); resp.body["error_description"] != "this issuer issues no JWT-SVIDs" {
		t.Errorf("an unauthenticated JWT request without a key: %d %v", resp.status, resp.body)
	}
	svidKey := newKey(t)
	f.verifyX509(t, f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, svidKey, nil)))), "spiffe://example.org/vms/billing", svidKey)

	var jwks jose.JSONWebKeySet
	getJSON(t, f.srv, f.iss.URL()+JWKSPath, &jwks)
	if len(jwks.Keys) != 0 {
		t.Errorf("the JWKS still holds %d keys", len(jwks.Keys))
	}
	body := getBody(t, f.iss.URL()+JWKSPath)
	if !strings.Contains(body, `"keys":[]`) {
		t.Errorf("the JWKS is %q, want an empty key list and not null", body)
	}
	var doc map[string]any
	getJSON(t, f.srv, f.iss.URL()+DiscoveryPath, &doc)
	if algs, ok := doc["id_token_signing_alg_values_supported"].([]any); !ok || len(algs) != 2 || algs[0] != "ES256" || algs[1] != "RS256" {
		t.Errorf("signing algorithms = %v, want what the issuer can sign with", doc["id_token_signing_alg_values_supported"])
	}
	if doc["spiffex_x509_svid_supported"] != true || doc["jwks_uri"] == nil || doc["token_endpoint"] == nil {
		t.Errorf("discovery lost more than the algorithms: %v", doc)
	}
	bundle, err := spiffebundle.Parse(td, []byte(getBody(t, f.iss.URL()+BundlePath)))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.JWTAuthorities()) != 0 || len(bundle.X509Authorities()) != 1 {
		t.Errorf("bundle: %d JWT and %d X.509 authorities, want 0 and 1", len(bundle.JWTAuthorities()), len(bundle.X509Authorities()))
	}
	if _, ok := bundle.SequenceNumber(); !ok {
		t.Error("the bundle has no sequence number")
	}

	back, err := keyset.Add(keysDir, keyset.ES256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !watcher.Reload() {
		t.Fatal("the new key was not noticed")
	}
	resp = jwtRequest()
	if resp.status != http.StatusOK {
		t.Fatalf("JWT-SVID after a key came back: %d %v", resp.status, resp.body)
	}
	if kid := kidOf(t, resp.body["access_token"].(string)); kid != back.ID {
		t.Errorf("signed with %s, want the new key %s", kid, back.ID)
	}
	getJSON(t, f.srv, f.iss.URL()+JWKSPath, &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != back.ID {
		t.Errorf("JWKS after the key came back: %d keys", len(jwks.Keys))
	}
}

// An empty set is not a set of exposed keys: Mint says which it is.
func TestMintWithoutKeys(t *testing.T) {
	f := newTokenFixture(t)
	if !f.iss.hasJWTKeys() {
		t.Fatal("the fixture has no keys")
	}
	f.iss.cfg.Keys = staticKeys{set: keyset.EmptySet(), seq: 1}
	if f.iss.hasJWTKeys() {
		t.Error("an empty set has keys")
	}
	if _, _, err := f.iss.Mint(spiffeid.RequireFromPath(td, "/x"), []string{"orders"}); !errors.Is(err, errNoJWTKeys) {
		t.Errorf("Mint without keys: %v", err)
	}
}

func kidOf(t *testing.T, token string) string {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Headers[0].KeyID
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// With every key and every CA file gone the bundle is still a document a
// consumer can read as "nothing": an empty key list, never null.
func TestBundleWithNothingLeftHasAnEmptyKeyList(t *testing.T) {
	keysDir := t.TempDir()
	if _, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	watcher, err := keyset.NewWatcher(keysDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	caDir := t.TempDir()
	if _, err := ca.Init(caDir, td, time.Now().Add(-48*time.Hour), longValidity); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.NewWatcher(ca.Options{Dir: caDir, TrustDomain: td, ActivationDelay: DefaultActivationDelay, Retention: ca.Retention(DefaultX509SVIDTTL)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		cfg.Keys = watcher
		cfg.CA = authority
	})
	for _, dir := range []string{keysDir, caDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	watcher.Reload()
	watcher.Reload()
	authority.Reload()
	body := getBody(t, f.iss.URL()+BundlePath)
	if !strings.Contains(body, `"keys":[]`) || strings.Contains(body, "null") {
		t.Errorf("bundle %q, want an empty key list", body)
	}
}
