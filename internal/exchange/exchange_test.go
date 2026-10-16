package exchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/PeterSR/spiffex/internal/state"
)

const (
	k8sIssuer = "https://kubernetes.default.svc.cluster.local"
	audience  = "https://issuer.example.org/origins/kube"
)

type upstreamKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newUpstreamKey(t *testing.T, kid string) upstreamKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return upstreamKey{k, kid}
}

func (k upstreamKey) jwks() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "ES256", Use: "sig"}}}
}

func (k upstreamKey) signRaw(t *testing.T, payload string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (k upstreamKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return k.signRaw(t, string(payload))
}

// serviceAccountClaims looks like a Kubernetes projected service account token.
func serviceAccountClaims(lifetime time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": k8sIssuer,
		"sub": "system:serviceaccount:shop:billing",
		"aud": []string{audience},
		"exp": now.Add(lifetime).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      "shop",
			"serviceaccount": map[string]any{"name": "billing"},
		},
	}
}

func with(claims map[string]any, key string, value any) map[string]any {
	claims[key] = value
	return claims
}

func without(claims map[string]any, key string) map[string]any {
	delete(claims, key)
	return claims
}

func origin() *state.ExpandedJWT {
	return &state.ExpandedJWT{Issuer: k8sIssuer, Audience: audience, MaxTokenLifetime: time.Hour}
}

func verify(t *testing.T, key upstreamKey, token string) (map[string]any, error) {
	t.Helper()
	parsed, err := Parse(token)
	if err != nil {
		return nil, err
	}
	return parsed.Verify(context.Background(), origin(), StaticKeys{key.jwks()}, time.Now())
}

func TestVerify(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	claims, err := verify(t, key, key.sign(t, serviceAccountClaims(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := state.ClaimValue(claims, "kubernetes.io/serviceaccount/name"); v != "billing" {
		t.Errorf("claims = %v", claims)
	}
	// Kubernetes adds a few seconds to the lifetimes it is asked for.
	if _, err := verify(t, key, key.sign(t, serviceAccountClaims(time.Hour+7*time.Second))); err != nil {
		t.Errorf("a 3607 second token: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	key, stranger := newUpstreamKey(t, "k1"), newUpstreamKey(t, "k1")
	now := time.Now()
	cases := map[string]string{
		"signed by another key": stranger.sign(t, serviceAccountClaims(time.Hour)),
		"expired":               key.sign(t, with(serviceAccountClaims(time.Hour), "exp", now.Add(-time.Minute).Unix())),
		"not yet valid":         key.sign(t, with(serviceAccountClaims(time.Hour), "nbf", now.Add(time.Hour).Unix())),
		"no exp":                key.sign(t, without(serviceAccountClaims(time.Hour), "exp")),
		"no iat":                key.sign(t, without(serviceAccountClaims(time.Hour), "iat")),
		"lives too long":        key.sign(t, serviceAccountClaims(time.Hour+31*time.Second)),
		"another audience":      key.sign(t, with(serviceAccountClaims(time.Hour), "aud", "elsewhere")),
		"another issuer":        key.sign(t, with(serviceAccountClaims(time.Hour), "iss", "https://elsewhere")),
		"duplicate claims":      key.signRaw(t, `{"iss":"`+k8sIssuer+`","aud":"`+audience+`","exp":9999999999,"iat":9999990000,"sub":"a","sub":"b"}`),
		"HMAC":                  hs256(t, serviceAccountClaims(time.Hour)),
		"not a JWT":             "not-a-jwt",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verify(t, key, token); !errors.Is(err, ErrRejected) {
				t.Errorf("err = %v, want a rejection", err)
			}
		})
	}
}

func TestVerifyKeepsNumbersExact(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	now := time.Now().Unix()
	payload := `{"iss":"` + k8sIssuer + `","aud":"` + audience + `","exp":` + itoa(now+60) + `,"iat":` + itoa(now) + `,"id":12345678901234567890,"f":1.5}`
	claims, err := verify(t, key, key.signRaw(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := state.ClaimValue(claims, "id"); !ok || v != "12345678901234567890" {
		t.Errorf("id = %q (%v), want the integer exactly as written", v, ok)
	}
	if _, ok := state.ClaimValue(claims, "f"); ok {
		t.Error("a fraction counted as a value")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func hs256(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestUnverifiedIssuers(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := map[string][]string{
		enc(`{"alg":"none"}`) + "." + enc(`{"iss":"a"}`) + ".":                                                            {"a"},
		enc(`{"alg":"HS256"}`) + "." + enc(`{"iss":"a","iss":"b"}`) + ".x":                                                {"a", "b"},
		"x." + base64.StdEncoding.EncodeToString([]byte(`{"iss":"a?>"}`)) + ".y":                                          {"a?>"},
		"x." + base64.URLEncoding.EncodeToString([]byte(`{"iss":"ab"}`)) + ".y":                                           {"ab"},
		`{"payload":"` + enc(`{"iss":"a"}`) + `","signatures":[]}`:                                                        {"a"},
		` {"protected":"x","payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"iss":"a"}`)) + `","signature":"y"}`: {"a"},
		`{"payload": 7}`:                nil,
		"opaque-proof":                  nil,
		"a.b.c":                         nil,
		"x." + enc(`["iss"]`) + ".y":    nil,
		"x." + enc(`{"sub":"a"}`) + ".": nil,
	}
	for token, want := range cases {
		if got := UnverifiedIssuers(token); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("UnverifiedIssuers(%q) = %v, want %v", token, got, want)
		}
	}
}

// keyServer serves a discovery document and a JWK Set over TLS, and writes
// its CA certificate to a file for RemoteKeys to trust.
type keyServer struct {
	*httptest.Server
	caFile  string
	keys    atomic.Pointer[jose.JSONWebKeySet]
	fetches atomic.Int32
	// authorized counts requests that carried the bearer token, by path.
	authorized map[string]*atomic.Int32
	jwksURI    string
}

func newKeyServer(t *testing.T, key upstreamKey) *keyServer {
	t.Helper()
	ks := &keyServer{authorized: map[string]*atomic.Int32{"/.well-known/openid-configuration": {}, "/keys": {}}}
	ks.keys.Store(key.jwks())
	ks.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := ks.authorized[r.URL.Path]; c != nil && r.Header.Get("Authorization") == "Bearer sa-token" {
			c.Add(1)
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jwksURI := ks.jwksURI
			if jwksURI == "" {
				jwksURI = ks.URL + "/keys"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": ks.URL, "jwks_uri": jwksURI})
		case "/keys":
			ks.fetches.Add(1)
			_ = json.NewEncoder(w).Encode(ks.keys.Load())
		case "/redirect":
			http.Redirect(w, r, "/keys", http.StatusFound)
		case "/huge":
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("x", maxJWKSBody) + `"}`))
		case "/many":
			set := jose.JSONWebKeySet{}
			for range maxJWKSKeys + 1 {
				set.Keys = append(set.Keys, key.jwks().Keys[0])
			}
			_ = json.NewEncoder(w).Encode(set)
		}
	}))
	t.Cleanup(ks.Close)
	ks.caFile = filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ks.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ks.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return ks
}

func (ks *keyServer) host() string { return strings.TrimPrefix(ks.URL, "https://") }

func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// waitIdle waits for a background refresh, if one runs.
func (r *RemoteKeys) waitIdle() {
	r.mu.Lock()
	wait := r.refreshing
	r.mu.Unlock()
	if wait != nil {
		<-wait
	}
}

func TestRemoteKeysCaching(t *testing.T) {
	first, second := newUpstreamKey(t, "first"), newUpstreamKey(t, "second")
	ks := newKeyServer(t, first)
	remote := &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile}
	ctx := context.Background()

	set, err := remote.Keys(ctx, "first")
	if err != nil || len(set.Key("first")) != 1 {
		t.Fatalf("first fetch: %v %v", set, err)
	}
	if _, err := remote.Keys(ctx, "first"); err != nil || ks.fetches.Load() != 1 {
		t.Errorf("a known key was refetched: %d fetches, %v", ks.fetches.Load(), err)
	}
	// A key the cache lacks triggers a refetch, but only once per interval,
	// and the first token signed with the new key already succeeds.
	ks.keys.Store(second.jwks())
	remote.mu.Lock()
	remote.attempted = time.Now().Add(-jwksMinRefetch)
	remote.mu.Unlock()
	if set, _ := remote.Keys(ctx, "second"); len(set.Key("second")) != 1 {
		t.Error("an unknown kid did not wait for the refetch")
	}
	for range 5 {
		_, _ = remote.Keys(ctx, "third")
		remote.waitIdle()
	}
	if n := ks.fetches.Load(); n != 2 {
		t.Errorf("%d fetches, want 2: unknown kids must not trigger a fetch each", n)
	}

	// Keys that could not be refreshed for too long are no longer trusted.
	ks.Close()
	remote.mu.Lock()
	remote.fetched = time.Now().Add(-jwksMaxStale - time.Minute)
	remote.attempted = time.Time{}
	remote.mu.Unlock()
	if _, err := remote.Keys(ctx, "second"); err == nil {
		t.Error("keys older than the staleness limit were served with the upstream down")
	}
}

func TestRemoteKeysLimits(t *testing.T) {
	key := newUpstreamKey(t, "k")
	ks := newKeyServer(t, key)
	for _, path := range []string{"/redirect", "/huge", "/many", "/missing"} {
		remote := &RemoteKeys{URL: ks.URL + path, CAFile: ks.caFile}
		if _, err := remote.Keys(context.Background(), ""); err == nil {
			t.Errorf("%s: fetched keys", path)
		}
	}
	if _, err := (&RemoteKeys{URL: "http://example.org/keys"}).Keys(context.Background(), ""); err == nil {
		t.Error("fetched keys over plain http")
	}
	remote := &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, RefusePrivateAddresses: true}
	if _, err := remote.Keys(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Errorf("fetched from a loopback address while refusing private ones: %v", err)
	}
	u, err := url.Parse(ks.URL)
	if err != nil {
		t.Fatal(err)
	}
	remote = &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, RefusePrivateAddresses: true, AllowPrivateHosts: []string{"127.0.0.1:1"}}
	if _, err := remote.Keys(context.Background(), ""); err == nil {
		t.Error("an exempt host was let through on a port not exempt")
	}
	remote = &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, RefusePrivateAddresses: true, AllowPrivateHosts: []string{u.Host}}
	if _, err := remote.Keys(context.Background(), ""); err != nil {
		t.Errorf("an exempt host and port was refused: %v", err)
	}
}

// The bearer token goes only to an allowed host, and only to the host the
// origin names: with discovery, never to the location the discovery
// document gives.
func TestRemoteKeysBearerToken(t *testing.T) {
	key := newUpstreamKey(t, "k")
	ks := newKeyServer(t, key)
	token := tokenFile(t)
	ctx := context.Background()

	remote := &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, BearerTokenFile: token, BearerHosts: []string{ks.host()}}
	if _, err := remote.Keys(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if ks.authorized["/keys"].Load() != 1 {
		t.Error("the bearer token was not sent to the allowed jwks_uri host")
	}

	remote = &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, BearerTokenFile: token, BearerHosts: []string{"elsewhere.example"}}
	if _, err := remote.Keys(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if ks.authorized["/keys"].Load() != 1 {
		t.Error("the bearer token was sent to a host the settings do not allow")
	}

	remote = &RemoteKeys{URL: ks.URL + "/keys", CAFile: ks.caFile, BearerTokenFile: token, BearerHosts: []string{ks.host()}, BearerPaths: []string{"/openid/v1/jwks"}}
	if _, err := remote.Keys(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if ks.authorized["/keys"].Load() != 1 {
		t.Error("the bearer token was sent to a path the settings do not allow")
	}

	remote = &RemoteKeys{URL: ks.URL, Discover: true, CAFile: ks.caFile, BearerTokenFile: token, BearerHosts: []string{ks.host()}}
	if _, err := remote.Keys(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if ks.authorized["/.well-known/openid-configuration"].Load() != 1 || ks.authorized["/keys"].Load() != 1 {
		t.Error("with discovery, the bearer token must go with the discovery request and nowhere else")
	}
}

func TestPublicAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false,
		"::ffff:8.8.8.8": true, "224.0.0.1": false,
		"64:ff9b::a00:1": false, "64:ff9b::808:808": true, // NAT64
		"2002:a00:1::1": false, "2002:808:808::1": true, // 6to4
		"::a00:1": false, "::808:808": true, // IPv4-compatible
	} {
		if got := publicAddress(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddress(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestFileKeysReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	write := func(k upstreamKey, mtime time.Time) {
		data, err := json.Marshal(k.jwks())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	a, b := newUpstreamKey(t, "a"), newUpstreamKey(t, "b")
	write(a, time.Now().Add(-time.Hour))
	f := &FileKeys{Path: path}
	if set, err := f.Keys(context.Background(), ""); err != nil || len(set.Key("a")) != 1 {
		t.Fatalf("%v %v", set, err)
	}
	write(b, time.Now())
	if set, err := f.Keys(context.Background(), ""); err != nil || len(set.Key("b")) != 1 {
		t.Errorf("file change not picked up: %v %v", set, err)
	}
	if err := os.WriteFile(path, []byte("secret content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Keys(context.Background(), ""); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("a broken file: %v; want an error that does not quote it", err)
	}
}
