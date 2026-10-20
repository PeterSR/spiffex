package issuer

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/federation"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

type staticCA struct {
	set *ca.Set
	seq uint64
}

func (s staticCA) Current() (*ca.Set, uint64, <-chan struct{}) { return s.set, s.seq, nil }

// testCAIssuer is testIssuer with a CA made in a directory of its own, root
// of the trust domain, valid from two days ago.
func testCAIssuer(t *testing.T, mutate func(dir string)) (*Issuer, *httptest.Server, []*x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	made, err := ca.Init(dir, td, time.Now().Add(-48*time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, name := range []string{made.File, made.KeyFile} {
		if err := os.Chtimes(filepath.Join(dir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if mutate != nil {
		mutate(dir)
	}
	set, err := ca.Load(ca.Options{Dir: dir, TrustDomain: td, ActivationDelay: DefaultActivationDelay, Retention: ca.Retention(DefaultX509SVIDTTL)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	if _, err := keyset.Add(keys, keyset.ES256, old); err != nil {
		t.Fatal(err)
	}
	keySet, err := keyset.LoadDir(keys)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	iss, err := New(Config{
		URL:         srv.URL,
		TrustDomain: td,
		Keys:        staticKeys{set: keySet, seq: 7},
		CA:          staticCA{set: set, seq: 1000},
		Policy:      emptyPolicy,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = iss.Handler()
	var anchors []*x509.Certificate
	for _, a := range set.Anchors() {
		anchors = append(anchors, a.Cert)
	}
	return iss, srv, anchors
}

func TestBundleCarriesX509Authorities(t *testing.T) {
	iss, srv, anchors := testCAIssuer(t, nil)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	bundle, err := federation.FetchBundle(context.Background(), td, iss.URL()+BundlePath, federation.WithWebPKIRoots(roots))
	if err != nil {
		t.Fatal(err)
	}
	got := bundle.X509Authorities()
	if len(got) != 1 || !got[0].Equal(anchors[0]) {
		t.Fatalf("X.509 authorities = %d, want the root", len(got))
	}
	if len(bundle.JWTAuthorities()) != 1 {
		t.Errorf("%d JWT authorities, want 1", len(bundle.JWTAuthorities()))
	}
	if seq, ok := bundle.SequenceNumber(); !ok || seq != 7+1000 {
		t.Errorf("sequence number = %d (%v), want the sum of both sets' sequences", seq, ok)
	}

	// The raw document: use x509-svid, the key's parameters and one x5c
	// element.
	var doc struct {
		Keys []struct {
			Use string   `json:"use"`
			Kty string   `json:"kty"`
			Crv string   `json:"crv"`
			X5c []string `json:"x5c"`
			Kid string   `json:"kid"`
		} `json:"keys"`
	}
	getJSON(t, srv, iss.URL()+BundlePath, &doc)
	var x509Keys int
	for _, k := range doc.Keys {
		switch k.Use {
		case "x509-svid":
			x509Keys++
			if k.Kty != "EC" || k.Crv != "P-256" || len(k.X5c) != 1 {
				t.Errorf("X.509 key = %+v", k)
			}
		case "jwt-svid":
			if k.Kid == "" {
				t.Error("a JWT key without kid")
			}
		default:
			t.Errorf("key with use %q", k.Use)
		}
	}
	if x509Keys != 1 || len(doc.Keys) != 2 {
		t.Errorf("%d keys, %d of them X.509; want 2 and 1", len(doc.Keys), x509Keys)
	}
}

// OIDC consumers never see X.509 authorities.
func TestJWKSNeverHoldsX509Authorities(t *testing.T) {
	iss, srv, _ := testCAIssuer(t, nil)
	var jwks jose.JSONWebKeySet
	getJSON(t, srv, iss.URL()+JWKSPath, &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Use != "sig" || len(jwks.Keys[0].Certificates) != 0 {
		t.Errorf("JWKS = %+v", jwks)
	}
}

func TestBundleWithoutACAIsUnchanged(t *testing.T) {
	iss, srv := testIssuer(t, "", keyset.ES256)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	bundle, err := federation.FetchBundle(context.Background(), td, iss.URL()+BundlePath, federation.WithWebPKIRoots(roots))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.X509Authorities()) != 0 {
		t.Error("X.509 authorities without a CA")
	}
	if seq, _ := bundle.SequenceNumber(); seq != 7 {
		t.Errorf("sequence = %d, want the keys' own", seq)
	}
	var doc map[string]any
	getJSON(t, srv, iss.URL()+DiscoveryPath, &doc)
	if _, ok := doc["spiffex_x509_svid_supported"]; ok {
		t.Error("discovery announces X.509-SVIDs without a CA")
	}
}

func TestDiscoveryAnnouncesX509OnlyWithAUsableCA(t *testing.T) {
	iss, srv, _ := testCAIssuer(t, nil)
	var doc map[string]any
	getJSON(t, srv, iss.URL()+DiscoveryPath, &doc)
	if doc["spiffex_x509_svid_supported"] != true {
		t.Errorf("spiffex_x509_svid_supported = %v, want true", doc["spiffex_x509_svid_supported"])
	}

	// The same CA once it has expired: no usable CA, no announcement.
	iss.cfg.Now = func() time.Time { return time.Now().Add(2 * 365 * 24 * time.Hour) }
	doc = nil
	getJSON(t, srv, iss.URL()+DiscoveryPath, &doc)
	if _, ok := doc["spiffex_x509_svid_supported"]; ok {
		t.Error("announced X.509-SVIDs with an expired CA")
	}
	var seen struct{ Keys []any }
	getJSON(t, srv, iss.URL()+BundlePath, &seen)
	if len(seen.Keys) != 2 {
		t.Errorf("an expired anchor is still published until its retention ends: %d keys", len(seen.Keys))
	}
}

func TestConfigValidatesX509SVIDTTL(t *testing.T) {
	_, srv := testIssuer(t, "", keyset.ES256)
	base := Config{URL: srv.URL, TrustDomain: td, Keys: staticKeys{}, Policy: emptyPolicy}
	for _, ttl := range []time.Duration{time.Minute, 25 * time.Hour} {
		cfg := base
		cfg.X509SVIDTTL = ttl
		if _, err := New(cfg); err == nil {
			t.Errorf("X.509-SVID TTL %s accepted", ttl)
		}
	}
	cfg := base
	if iss, err := New(cfg); err != nil || iss.cfg.X509SVIDTTL != time.Hour {
		t.Errorf("default TTL: %v", err)
	}
}
