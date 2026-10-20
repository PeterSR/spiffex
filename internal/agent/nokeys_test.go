package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
)

type realRig struct {
	agent     *Agent
	addr      string
	keysDir   string
	watcher   *keyset.Watcher
	caDir     string
	authority *ca.Watcher
}

func newRealRig(t *testing.T, withKey bool) *realRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	keysDir := t.TempDir()
	if withKey {
		if _, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	watcher, err := keyset.NewWatcherAllowingNoKeys(keysDir, quiet())
	if err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(t.TempDir(), "ca")
	if _, err := ca.Init(caDir, td, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.NewWatcher(ca.Options{Dir: caDir, TrustDomain: td, ActivationDelay: issuer.DefaultActivationDelay, Retention: ca.Retention(issuer.DefaultX509SVIDTTL)}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	iss, err := issuer.New(issuer.Config{URL: srv.URL, TrustDomain: td, Keys: watcher, CA: authority,
		Policy: workloadPolicy(t, srv.URL, &clientKey.PublicKey), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	h := iss.Handler()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) })
	client, err := Discover(ctx, srv.URL, spiffeid.TrustDomain{}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Issuer: client, Credential: PrivateKeyJWT{ClientID: "workloads/billing", Key: clientKey}, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	go a.Run(ctx)
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	g := a.NewServer()
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	return &realRig{agent: a, addr: "unix://" + sock, keysDir: keysDir, watcher: watcher, caDir: caDir, authority: authority}
}

func waitAuthorities(t *testing.T, src *workloadapi.JWTSource, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := src.GetJWTBundleForTrustDomain(td)
		if err == nil && len(b.JWTAuthorities()) == want {
			return
		}
		if time.Now().After(deadline) {
			n := -1
			if b != nil {
				n = len(b.JWTAuthorities())
			}
			t.Fatalf("source never saw %d authorities (have %d, err %v)", want, n, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// removeAll deletes every file in dir.
func removeAll(t *testing.T, dir string) {
	t.Helper()
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

// removeKeys removes the JWT keys and takes the issuer through the two polls
// that confirm it.
func (r *realRig) removeKeys(t *testing.T) {
	t.Helper()
	removeAll(t, r.keysDir)
	r.watcher.Reload()
	if !r.watcher.Reload() {
		t.Fatal("the removal was not noticed")
	}
}

// Removing the last JWT key revokes what it signed, all the way to the
// workload: an open go-spiffe JWTSource gets the empty set and stays up, the
// agent stops handing out cached tokens the key signed, and a key that comes
// back signs tokens that validate.
func TestRemovedJWTKeyRevokesCachedTokens(t *testing.T) {
	r := newRealRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	src, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(r.addr)))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	waitAuthorities(t, src, 1)
	old, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtsvid.ParseAndValidate(old.Marshal(), src, []string{"orders"}); err != nil {
		t.Fatal(err)
	}

	r.removeKeys(t)
	r.agent.refreshBundle(ctx)
	waitAuthorities(t, src, 0)
	if _, err := jwtsvid.ParseAndValidate(old.Marshal(), src, []string{"orders"}); err == nil {
		t.Error("the old token still validates against the source")
	}
	if _, err := workloadapi.ValidateJWTSVID(ctx, old.Marshal(), "orders", workloadapi.WithAddr(r.addr)); err == nil {
		t.Error("the agent validated a token of the removed key")
	}
	for _, audience := range []string{"orders", "payments"} {
		_, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
		if err == nil || !strings.Contains(err.Error(), "issues no JWT-SVIDs") {
			t.Errorf("FetchJWTSVID(%s) with no key: %v, want the no-JWT error and not the cached token", audience, err)
		}
	}
	fresh, err := workloadapi.New(ctx, workloadapi.WithAddr(r.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.FetchJWTBundles(ctx); err != nil {
		t.Errorf("a new client on an empty set: %v", err)
	}

	if _, err := keyset.Add(r.keysDir, keyset.ES256, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.watcher.Reload()
	r.agent.refreshBundle(ctx)
	waitAuthorities(t, src, 1)
	renewed, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Marshal() == old.Marshal() {
		t.Error("the token of the removed key came back from the cache")
	}
	if _, err := jwtsvid.ParseAndValidate(renewed.Marshal(), src, []string{"orders"}); err != nil {
		t.Errorf("the new token: %v", err)
	}
}

// An issuer that lost every key and every CA file serves a bundle with an
// empty key list. The agent takes it as the revocation it is: JWT streams get
// the empty set and X.509 streams never get an empty bundle.
func TestAgentTakesABundleWithNoAuthorities(t *testing.T) {
	r := newRealRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	src, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(r.addr)))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	waitAuthorities(t, src, 1)
	old, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}

	api := workload.NewSpiffeWorkloadAPIClient(dialAgent(t, r.addr))
	header := metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
	x509Bundles, err := api.FetchX509Bundles(header, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := x509Bundles.Recv()
	if err != nil || len(first.Bundles) != 1 {
		t.Fatalf("first X.509 bundle: %v %v", first, err)
	}

	r.removeKeys(t)
	removeAll(t, r.caDir)
	r.authority.Reload()
	r.agent.refreshBundle(ctx)
	waitAuthorities(t, src, 0)
	if _, err := workloadapi.ValidateJWTSVID(ctx, old.Marshal(), "orders", workloadapi.WithAddr(r.addr)); err == nil {
		t.Error("the agent validated a token of the removed key")
	}
	if b, _ := r.agent.currentBundle(); len(b.JWTAuthorities()) != 0 || len(b.X509Authorities()) != 0 {
		t.Errorf("the agent kept %d JWT and %d X.509 authorities", len(b.JWTAuthorities()), len(b.X509Authorities()))
	}
	got := make(chan error, 1)
	go func() {
		_, err := x509Bundles.Recv()
		got <- err
	}()
	select {
	case err := <-got:
		// Without a CA the issuer announces no X.509-SVIDs, which ends the
		// stream; what it must never do is send an empty bundle.
		if status.Code(err) != codes.Unimplemented {
			t.Errorf("the X.509 stream after the roots were gone: %v, want it to end with Unimplemented", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("the X.509 stream neither ended nor sent")
	}
}

func dialAgent(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// A document with an empty key list parses as a bundle with no authority,
// and one without the list does not.
func TestFetchBundleReadsAnEmptyKeyList(t *testing.T) {
	serve := func(body string) *IssuerClient {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/bundle") {
				_, _ = w.Write([]byte(body))
				return
			}
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q,"spiffe_bundle_endpoint":%q,"spiffe_trust_domain":"example.org"}`, srv.URL, srv.URL+"/token", srv.URL+"/bundle")
		}))
		t.Cleanup(srv.Close)
		client, err := Discover(context.Background(), srv.URL, td, nil)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	b, err := serve(`{"keys":[],"spiffe_sequence":9,"spiffe_refresh_hint":3}`).FetchBundle(context.Background())
	if err != nil || len(b.JWTAuthorities()) != 0 || len(b.X509Authorities()) != 0 {
		t.Fatalf("an empty key list: %v", err)
	}
	if seq, ok := b.SequenceNumber(); !ok || seq != 9 {
		t.Errorf("sequence %d (%v)", seq, ok)
	}
	if hint, ok := b.RefreshHint(); !ok || hint != 3*time.Second {
		t.Errorf("refresh hint %v (%v)", hint, ok)
	}
	for _, body := range []string{`{"keys":null}`, `{}`, `{"keys":"x"}`, `not json`} {
		if _, err := serve(body).FetchBundle(context.Background()); err == nil {
			t.Errorf("%s was accepted as a bundle", body)
		}
	}
}

// A token request in flight when the last key is removed and the bundle
// refreshes is answered but not cached: its key is already gone.
func TestTokenInFlightDuringKeyRemovalIsNotCached(t *testing.T) {
	r := newRealRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Wait for the agent's first bundle so the cache has something to judge by.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, _ := r.agent.currentBundle(); b != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no bundle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The token is minted with the key, then held back until the key is gone.
	release := make(chan struct{})
	reached := make(chan struct{})
	r.agent.issuer.httpClient.Transport = holdTokenResponse{inner: r.agent.issuer.httpClient.Transport, reached: reached, release: release}

	done := make(chan error, 1)
	go func() {
		conn := dialAgent(t, r.addr)
		_, err := workload.NewSpiffeWorkloadAPIClient(conn).FetchJWTSVID(
			metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true"), &workload.JWTSVIDRequest{Audience: []string{"orders"}})
		done <- err
	}()
	select {
	case <-reached:
	case <-ctx.Done():
		t.Fatal("the token request never reached the issuer")
	}
	r.removeKeys(t)
	r.agent.refreshBundle(ctx)
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the waiting caller: %v", err)
	}
	r.agent.tokenMu.Lock()
	n := len(r.agent.tokens)
	r.agent.tokenMu.Unlock()
	if n != 0 {
		t.Errorf("%d tokens cached, want none: the key that signed them is gone", n)
	}
}

// holdTokenResponse lets a token response through only after release is
// closed, so the request is in flight while the test removes the key.
type holdTokenResponse struct {
	inner   http.RoundTripper
	reached chan struct{}
	release chan struct{}
}

func (h holdTokenResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	inner := h.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	resp, err := inner.RoundTrip(req)
	if err == nil && strings.HasSuffix(req.URL.Path, "/token") {
		close(h.reached)
		<-h.release
	}
	return resp, err
}
