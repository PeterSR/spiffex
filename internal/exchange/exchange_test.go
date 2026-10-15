package exchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

const (
	k8sIssuer = "https://kubernetes.default.svc.cluster.local"
	self      = "https://issuer.example.org"
)

type staticKeys struct{ set *jose.JSONWebKeySet }

func (s staticKeys) Keys(context.Context, string) (*jose.JSONWebKeySet, error) { return s.set, nil }

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

// serviceAccountClaims looks like a Kubernetes projected service account token.
func serviceAccountClaims(namespace, name string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": k8sIssuer,
		"sub": "system:serviceaccount:" + namespace + ":" + name,
		"aud": []string{"spiffex"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": name, "uid": "8f2c"},
		},
	}
}

func (k upstreamKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newExchanger(t *testing.T, key upstreamKey) *Exchanger {
	t.Helper()
	e, err := New(td, self, []Upstream{{
		Name:     "kubernetes",
		Issuer:   k8sIssuer,
		Audience: "spiffex",
		Keys:     staticKeys{key.jwks()},
		Rules: []Rule{
			{Match: map[string]string{"kubernetes.io/namespace": "kube-system"}, SPIFFEID: "spiffe://example.org/system/{kubernetes.io/serviceaccount/name}"},
			{SPIFFEID: "spiffe://example.org/ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}"},
		},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExchange(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	e := newExchanger(t, key)
	cases := map[string]struct {
		claims map[string]any
		want   string
	}{
		"general rule":     {serviceAccountClaims("shop", "billing"), "spiffe://example.org/ns/shop/sa/billing"},
		"first rule wins":  {serviceAccountClaims("kube-system", "coredns"), "spiffe://example.org/system/coredns"},
		"dots and dashes":  {serviceAccountClaims("shop-2", "billing.v2"), "spiffe://example.org/ns/shop-2/sa/billing.v2"},
		"audience in list": {with(serviceAccountClaims("shop", "billing"), "aud", []string{"other", "spiffex"}), "spiffe://example.org/ns/shop/sa/billing"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			id, err := e.Exchange(context.Background(), key.sign(t, c.claims))
			if err != nil {
				t.Fatal(err)
			}
			if id.String() != c.want {
				t.Errorf("got %s, want %s", id, c.want)
			}
		})
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

func TestExchangeRejects(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	stranger := newUpstreamKey(t, "k1")
	e := newExchanger(t, key)
	sa := func() map[string]any { return serviceAccountClaims("shop", "billing") }
	nested := func(ns string) map[string]any {
		c := sa()
		c["kubernetes.io"].(map[string]any)["namespace"] = ns
		return c
	}

	cases := map[string]string{
		"unknown issuer":         key.sign(t, with(sa(), "iss", "https://elsewhere")),
		"own tokens":             key.sign(t, with(sa(), "iss", self)),
		"wrong audience":         key.sign(t, with(sa(), "aud", []string{"something-else"})),
		"no exp":                 key.sign(t, without(sa(), "exp")),
		"expired":                key.sign(t, with(sa(), "exp", time.Now().Add(-time.Hour).Unix())),
		"not yet valid":          key.sign(t, with(sa(), "nbf", time.Now().Add(time.Hour).Unix())),
		"signed by someone else": stranger.sign(t, sa()),
		"slash in a claim":       key.sign(t, nested("shop/sa/admin")),
		"dot-dot in a claim":     key.sign(t, nested("..")),
		"empty claim":            key.sign(t, nested("")),
		"percent in a claim":     key.sign(t, nested("shop%2Fadmin")),
		"claim missing":          key.sign(t, without(sa(), "kubernetes.io")),
		"HS256":                  hs256(t, sa()),
		"alg none":               unsigned(sa()),
		"garbage":                "not.a.token",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.Exchange(context.Background(), token)
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("err = %v, want a rejection", err)
			}
		})
	}
}

func hs256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func unsigned(claims map[string]any) string {
	body, _ := json.Marshal(claims)
	enc := func(b []byte) string { return strings.TrimRight(base64URL(b), "=") }
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(body) + "."
}

func TestNewRejectsBadUpstreams(t *testing.T) {
	keys := staticKeys{newUpstreamKey(t, "k").jwks()}
	good := func() Upstream {
		return Upstream{Name: "u", Issuer: k8sIssuer, Audience: "spiffex", Keys: keys, Rules: []Rule{{SPIFFEID: "spiffe://example.org/{sub}"}}}
	}
	cases := map[string]func(*Upstream){
		"no issuer":            func(u *Upstream) { u.Issuer = "" },
		"itself":               func(u *Upstream) { u.Issuer = self },
		"no audience":          func(u *Upstream) { u.Audience = "" },
		"no keys":              func(u *Upstream) { u.Keys = nil },
		"no rules":             func(u *Upstream) { u.Rules = nil },
		"foreign trust domain": func(u *Upstream) { u.Rules[0].SPIFFEID = "spiffe://other.org/{sub}" },
		"partial segment":      func(u *Upstream) { u.Rules[0].SPIFFEID = "spiffe://example.org/ns-{sub}" },
		"placeholder as host":  func(u *Upstream) { u.Rules[0].SPIFFEID = "spiffe://{sub}/x" },
		"unbalanced braces":    func(u *Upstream) { u.Rules[0].SPIFFEID = "spiffe://example.org/{sub" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := good()
			mutate(&u)
			if _, err := New(td, self, []Upstream{u}, nil); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := New(td, self, []Upstream{good(), good()}, nil); err == nil {
		t.Error("the same issuer twice was accepted")
	}
}

func TestRemoteKeys(t *testing.T) {
	first, second := newUpstreamKey(t, "first"), newUpstreamKey(t, "second")
	var current atomic.Pointer[jose.JSONWebKeySet]
	current.Store(first.jwks())
	var fetches atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			fetches.Add(1)
			if r.Header.Get("Authorization") != "Bearer sa-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(current.Load())
		}
	}))
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := &RemoteKeys{URL: srv.URL, Discover: true, Client: srv.Client(), BearerTokenFile: tokenFile}
	ctx := context.Background()

	set, err := remote.Keys(ctx, "first")
	if err != nil || len(set.Key("first")) != 1 {
		t.Fatalf("first fetch: %v %v", set, err)
	}
	if _, err := remote.Keys(ctx, "first"); err != nil || fetches.Load() != 1 {
		t.Errorf("a known key was refetched: %d fetches, %v", fetches.Load(), err)
	}
	// A key the cache lacks triggers a refetch in the background, but only
	// once per interval.
	current.Store(second.jwks())
	remote.mu.Lock()
	remote.attempted = time.Now().Add(-jwksMinRefetch)
	remote.mu.Unlock()
	// The first token signed with the new key already succeeds.
	if set, _ := remote.Keys(ctx, "second"); len(set.Key("second")) != 1 {
		t.Error("an unknown kid did not wait for the refetch")
	}
	for range 5 {
		_, _ = remote.Keys(ctx, "third")
		remote.waitIdle()
	}
	if n := fetches.Load(); n != 2 {
		t.Errorf("%d fetches, want 2: unknown kids must not trigger a fetch each", n)
	}

	// A caller that gives up at once does not cancel the refresh it started.
	current.Store(first.jwks())
	remote.mu.Lock()
	remote.attempted = time.Now().Add(-jwksMinRefetch)
	remote.mu.Unlock()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = remote.Keys(cancelled, "first-again")
	remote.waitIdle()
	if n := fetches.Load(); n != 3 {
		t.Errorf("%d fetches, want 3", n)
	}

	// Keys that could not be refreshed for too long are no longer trusted.
	srv.Close()
	remote.mu.Lock()
	remote.fetched = time.Now().Add(-jwksMaxStale - time.Minute)
	remote.attempted = time.Time{}
	remote.mu.Unlock()
	if _, err := remote.Keys(ctx, "first"); err == nil {
		t.Error("keys older than the staleness limit were served with the upstream down")
	}
}

func TestRemoteKeysRequiresHTTPS(t *testing.T) {
	remote := &RemoteKeys{URL: "http://example.org/keys"}
	if _, err := remote.Keys(context.Background(), ""); err == nil {
		t.Error("fetched keys over plain http")
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
}

func base64URL(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

// waitIdle waits for a background refresh, if one runs.
func (r *RemoteKeys) waitIdle() {
	r.mu.Lock()
	wait := r.refreshing
	r.mu.Unlock()
	if wait != nil {
		<-wait
	}
}

// The bearer token for fetching keys goes only to the configured host, even
// when the upstream's discovery document names another.
func TestRemoteKeysKeepsBearerTokenHome(t *testing.T) {
	var leaked atomic.Bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer elsewhere.Close()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": elsewhere.URL + "/keys"})
	}))
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(elsewhere.Certificate())
	remote := &RemoteKeys{URL: srv.URL, Discover: true, Client: client, BearerTokenFile: tokenFile}
	if _, err := remote.Keys(context.Background(), ""); err == nil {
		t.Error("fetched keys from another host with the bearer token configured")
	}
	if leaked.Load() {
		t.Error("the bearer token was sent to another host")
	}
}

// signRaw signs a payload written by hand, so the test controls exactly how
// numbers appear in the JSON.
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

// Numbers are compared exactly as the token wrote them, and only integers
// count, so no two different values can render the same SPIFFE ID.
func TestNumericClaims(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	e, err := New(td, self, []Upstream{{
		Name: "ci", Issuer: k8sIssuer, Audience: "spiffex", Keys: staticKeys{key.jwks()},
		Rules: []Rule{{Match: map[string]string{"owner_id": "9007199254740992"}, SPIFFEID: "spiffe://example.org/repo/{repo_id}"}},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := func(owner, repo string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":"spiffex","exp":%d,"owner_id":%s,"repo_id":%s}`,
			k8sIssuer, time.Now().Add(time.Hour).Unix(), owner, repo)
	}
	id, err := e.Exchange(context.Background(), key.signRaw(t, payload("9007199254740992", "12345678901234567890")))
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "spiffe://example.org/repo/12345678901234567890" {
		t.Errorf("got %s: a large integer lost precision", id)
	}
	for name, p := range map[string]string{
		"neighbouring integer": payload("9007199254740993", "1"),
		"fraction":             payload("9007199254740992.4", "1"),
		"exponent":             payload("9.007199254740992e15", "1"),
		"fractional template":  payload("9007199254740992", "0.1"),
		"boolean template":     payload("9007199254740992", "true"),
		"string true":          payload("9007199254740992", `"true"`),
	} {
		_, err := e.Exchange(context.Background(), key.signRaw(t, p))
		if name == "string true" {
			if err != nil {
				t.Errorf("%s: %v; a string claim is a plain segment", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v, want a rejection", name, err)
		}
	}
}

func TestLifetimeAndRequiredClaims(t *testing.T) {
	key := newUpstreamKey(t, "k1")
	e, err := New(td, self, []Upstream{{
		Name: "k", Issuer: k8sIssuer, Audience: "spiffex", Keys: staticKeys{key.jwks()}, MaxTokenLifetime: time.Hour,
		Rules: []Rule{{Require: []string{"kubernetes.io/pod/name"}, SPIFFEID: "spiffe://example.org/ns/{kubernetes.io/namespace}"}},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pod := func() map[string]any {
		c := serviceAccountClaims("shop", "billing")
		c["kubernetes.io"].(map[string]any)["pod"] = map[string]any{"name": "billing-7d9f", "uid": "1"}
		return c
	}
	if _, err := e.Exchange(context.Background(), key.sign(t, pod())); err != nil {
		t.Fatalf("a pod-bound token: %v", err)
	}
	longLived := with(pod(), "exp", time.Now().Add(365*24*time.Hour).Unix())
	for name, c := range map[string]map[string]any{
		"not bound to a pod": serviceAccountClaims("shop", "billing"),
		"year-long token":    longLived,
		"no iat":             without(pod(), "iat"),
	} {
		if _, err := e.Exchange(context.Background(), key.sign(t, c)); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v, want a rejection", name, err)
		}
	}
}
