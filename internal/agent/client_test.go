package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// fakeIssuer serves a discovery document and lets a test decide how the
// token endpoint answers.
func fakeIssuer(t *testing.T, token http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q,"spiffe_bundle_endpoint":%q,"spiffe_trust_domain":"example.org"}`,
			srv.URL, srv.URL+"/token", srv.URL+"/bundle")
	})
	mux.HandleFunc("/token", token)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testCredential(t *testing.T) Credential {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PrivateKeyJWT{ClientID: "billing", Key: key}
}

// A redirect from the token endpoint must not carry the credential anywhere.
func TestFetchTokenDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer elsewhere.Close()
	srv := fakeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	})
	client, err := Discover(context.Background(), srv.URL, spiffeid.TrustDomain{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchToken(context.Background(), testCredential(t), []string{"orders"}); err == nil {
		t.Error("a redirect was treated as success")
	}
	if leaked.Load() {
		t.Error("the credential was sent to the redirect target")
	}
}

func TestFetchTokenErrorClassification(t *testing.T) {
	cases := []struct {
		status   int
		body     string
		rejected bool
	}{
		{400, `{"error":"invalid_target"}`, true},
		{401, `{"error":"invalid_client","error_description":"client authentication failed"}`, true},
		{400, `{"error":"slow_down"}`, false},
		{429, `{"error":"invalid_request"}`, false},
		{500, `{"error":"server_error"}`, false},
		{502, `<html>bad gateway</html>`, false},
		{400, `not json`, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d %s", c.status, c.body), func(t *testing.T) {
			srv := fakeIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				fmt.Fprint(w, c.body)
			})
			client, err := Discover(context.Background(), srv.URL, spiffeid.TrustDomain{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.FetchToken(context.Background(), testCredential(t), []string{"orders"})
			var rejected *RejectedError
			if errors.As(err, &rejected) != c.rejected {
				t.Errorf("err = %v, rejected = %v, want %v", err, !c.rejected, c.rejected)
			}
		})
	}
}

func TestDiscoverRejects(t *testing.T) {
	serve := func(doc string) string {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, strings.ReplaceAll(doc, "$URL", srv.URL))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	good := `{"issuer":"$URL","token_endpoint":"$URL/token","spiffe_bundle_endpoint":"$URL/bundle","spiffe_trust_domain":"example.org"}`
	cases := map[string]struct {
		url string
		td  string
	}{
		"issuer mismatch":       {serve(`{"issuer":"https://other","token_endpoint":"$URL/token","spiffe_bundle_endpoint":"$URL/bundle","spiffe_trust_domain":"example.org"}`), ""},
		"endpoint elsewhere":    {serve(`{"issuer":"$URL","token_endpoint":"https://evil.example/token","spiffe_bundle_endpoint":"$URL/bundle","spiffe_trust_domain":"example.org"}`), ""},
		"trust domain mismatch": {serve(good), "other.org"},
		"plain http off-host":   {"http://issuer.example.org", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var td spiffeid.TrustDomain
			if c.td != "" {
				td = spiffeid.RequireTrustDomainFromString(c.td)
			}
			if _, err := Discover(context.Background(), c.url, td, nil); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := Discover(context.Background(), serve(good), spiffeid.RequireTrustDomainFromString("example.org"), nil); err != nil {
		t.Fatalf("matching trust domain: %v", err)
	}
}

// An issuer whose JWT keys were all removed still serves a bundle with its
// X.509 authorities, and the client takes it; a bundle with no authority of
// either kind is refused.
func TestFetchBundleAcceptsAnX509OnlyBundle(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	client, err := Discover(context.Background(), fake.srv.URL, td, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.FetchBundle(context.Background())
	if err != nil || len(bundle.JWTAuthorities()) != 1 || len(bundle.X509Authorities()) != 1 {
		t.Fatalf("both kinds: %v", err)
	}

	fake.withoutJWT.Store(true)
	bundle, err = client.FetchBundle(context.Background())
	if err != nil {
		t.Fatalf("an X.509-only bundle: %v", err)
	}
	if len(bundle.JWTAuthorities()) != 0 || len(bundle.X509Authorities()) != 1 {
		t.Errorf("%d JWT and %d X.509 authorities", len(bundle.JWTAuthorities()), len(bundle.X509Authorities()))
	}

	fake.supported.Store(false)
	if _, err := client.FetchBundle(context.Background()); err == nil {
		t.Errorf("a bundle with no authority: %v", err)
	}
}
