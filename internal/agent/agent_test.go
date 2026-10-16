package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// workloadPolicy has one keys origin at the root of the trust domain, with
// the billing workload as its member.
func workloadPolicy(t *testing.T, issuerURL string, key *ecdsa.PublicKey) *policy.Policy {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	st, err := state.ParseState([]byte(`
origins:
  workloads:
    provider: keys
    prefix: /
    audiences: [orders, payments, "` + issuerURL + `/manage"]
    members:
      billing: { keys: [` + string(pemKey) + `] }
`))
	if err != nil {
		t.Fatal(err)
	}
	p := policy.New(policy.Options{Settings: state.DefaultSettings(issuerURL, td)})
	if err := p.Apply(&store.Snapshot{Version: "1", State: st}); err != nil {
		t.Fatal(err)
	}
	return p
}

type fixture struct {
	srv *httptest.Server
	// onToken, when set, runs as each token request starts; the function it
	// returns runs when the request ends.
	onToken    atomic.Pointer[func() func()]
	agent      *Agent
	stopIssuer func()
	addr       string
	keysDir    string
	watcher    *keyset.Watcher
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newFixture runs an issuer over TLS and an agent for the "billing" workload
// on a Unix socket.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	keysDir := t.TempDir()
	if _, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	watcher, err := keyset.NewWatcher(keysDir, quiet())
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
	iss, err := issuer.New(issuer.Config{
		URL:         srv.URL,
		TrustDomain: td,
		Keys:        watcher,
		Policy:      workloadPolicy(t, srv.URL, &clientKey.PublicKey),
		Logger:      quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{srv: srv, stopIssuer: srv.Close, keysDir: keysDir, watcher: watcher}
	handler := iss.Handler()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hook := f.onToken.Load(); hook != nil && strings.HasSuffix(r.URL.Path, "/token") {
			defer (*hook)()()
		}
		handler.ServeHTTP(w, r)
	})

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
	grpcServer := a.NewServer()
	go func() { _ = grpcServer.Serve(l) }()
	t.Cleanup(grpcServer.Stop)

	f.agent, f.addr = a, "unix://"+sock
	return f
}

func (f *fixture) ctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestGoSPIFFEJWTSource(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(f.addr)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if svid.ID.String() != "spiffe://example.org/billing" {
		t.Errorf("SPIFFE ID = %s", svid.ID)
	}
	validated, err := jwtsvid.ParseAndValidate(svid.Marshal(), source, []string{"orders"})
	if err != nil {
		t.Fatal(err)
	}
	if validated.ID != svid.ID {
		t.Errorf("validated ID = %s", validated.ID)
	}
}

func TestGoSPIFFEClient(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(f.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	first, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Marshal() != again.Marshal() {
		t.Error("a fresh token was fetched although the cached one has most of its lifetime left")
	}

	validated, err := client.ValidateJWTSVID(ctx, first.Marshal(), "orders")
	if err != nil {
		t.Fatal(err)
	}
	if validated.ID != first.ID || validated.Claims["iss"] == nil || validated.Claims["jti"] == nil {
		t.Errorf("ValidateJWTSVID = %s %v", validated.ID, validated.Claims)
	}
	if _, err := client.ValidateJWTSVID(ctx, first.Marshal(), "payments"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("validating for the wrong audience: %v, want InvalidArgument", err)
	}

	bundles, err := client.FetchJWTBundles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := bundles.GetJWTBundleForTrustDomain(td); err != nil || len(b.JWTAuthorities()) != 1 {
		t.Errorf("JWT bundle: %v (%v)", b, err)
	}

	_, err = client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders", Subject: spiffeid.RequireFromPath(td, "/other")})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("asking for another identity: %v, want PermissionDenied", err)
	}
	_, err = client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "inventory"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("an audience the issuer refuses: %v, want PermissionDenied", err)
	}
}

func TestRawWorkloadAPI(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api := workload.NewSpiffeWorkloadAPIClient(conn)
	withHeader := metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")

	if _, err := api.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"orders"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("without the security header: %v, want InvalidArgument", err)
	}
	if _, err := api.FetchJWTSVID(withHeader, &workload.JWTSVIDRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("without an audience: %v, want InvalidArgument", err)
	}
	if _, err := api.ValidateJWTSVID(withHeader, &workload.ValidateJWTSVIDRequest{Audience: "orders"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("validating an empty token: %v, want InvalidArgument", err)
	}

	stream, err := api.FetchX509SVID(withHeader, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unimplemented {
		t.Errorf("FetchX509SVID: %v, want Unimplemented", err)
	}
	wit, err := api.FetchWITSVID(withHeader, &workload.WITSVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wit.Recv(); status.Code(err) != codes.Unimplemented {
		t.Errorf("FetchWITSVID: %v, want Unimplemented", err)
	}

	bundles, err := api.FetchJWTBundles(withHeader, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bundles.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.Bundles["spiffe://example.org"]; !ok || len(resp.Bundles) != 1 {
		t.Errorf("bundles keyed %v, want spiffe://example.org", keys(resp.Bundles))
	}
}

// A key added at the issuer reaches open FetchJWTBundles streams.
func TestBundleUpdatesAreStreamed(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(f.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	updates := make(chan int, 4)
	go func() {
		_ = client.WatchJWTBundles(ctx, watcherFunc(func(n int) { updates <- n }))
	}()
	if n := <-updates; n != 1 {
		t.Fatalf("first update has %d keys, want 1", n)
	}

	if _, err := keyset.Add(f.keysDir, keyset.ES256, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.watcher.Reload()
	f.agent.refreshBundle(ctx)
	select {
	case n := <-updates:
		if n != 2 {
			t.Errorf("update has %d keys, want 2", n)
		}
	case <-ctx.Done():
		t.Fatal("no update after the issuer published a new key")
	}
}

func TestListen(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")

	// A socket left behind by an agent that died is replaced.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	l, err := Listen(sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %v", info.Mode())
	}
	l.Close()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket left behind after Close: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("staging directory left behind: %v", entries)
	}

	// Anything that is not a socket is left alone.
	precious := filepath.Join(dir, "important.conf")
	if err := os.WriteFile(precious, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(precious, 0o600); err == nil {
		t.Error("Listen replaced a regular file")
	}
	if data, _ := os.ReadFile(precious); string(data) != "keep me" {
		t.Error("the regular file was changed")
	}
}

type watcherFunc func(keys int)

func (w watcherFunc) OnJWTBundlesUpdate(set *jwtbundle.Set) {
	b, err := set.GetJWTBundleForTrustDomain(td)
	if err == nil {
		w(len(b.JWTAuthorities()))
	}
}

func (watcherFunc) OnJWTBundlesWatchError(error) {}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAudienceHandling(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(f.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	both, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders", ExtraAudiences: []string{"payments"}})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "payments", ExtraAudiences: []string{"orders", "payments"}})
	if err != nil {
		t.Fatal(err)
	}
	if both.Marshal() != reordered.Marshal() {
		t.Error("the same audiences in another order fetched a new token")
	}
	if len(both.Audience) != 2 {
		t.Errorf("aud = %v, want both audiences", both.Audience)
	}

	for name, params := range map[string]jwtsvid.Params{
		"control character": {Audience: "orders\x00payments"},
		"too many":          {Audience: "a", ExtraAudiences: []string{"b", "c", "d", "e", "f"}},
		"the issuer itself": {Audience: f.agent.issuer.URL()},
	} {
		if _, err := client.FetchJWTSVID(ctx, params); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders", Subject: spiffeid.RequireFromPath(td, "/billing")}); err != nil {
		t.Errorf("asking for its own identity: %v", err)
	}
}

// With the issuer gone, cached tokens keep working and new ones are
// Unavailable, never PermissionDenied.
func TestIssuerUnavailable(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx(t)
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(f.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"}); err != nil {
		t.Fatal(err)
	}
	f.stopIssuer()
	if _, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"}); err != nil {
		t.Errorf("cached token: %v", err)
	}
	if _, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "payments"}); status.Code(err) != codes.Unavailable {
		t.Errorf("new token with the issuer down: %v, want Unavailable", err)
	}
}

func TestNoBundleYet(t *testing.T) {
	a, err := New(Config{Issuer: &IssuerClient{trustDomain: td}, Credential: testCredential(t), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ValidateJWTSVID(context.Background(), &workload.ValidateJWTSVIDRequest{Audience: "orders", Svid: "x.y.z"})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("ValidateJWTSVID before any bundle: %v, want Unavailable", err)
	}
}

func TestNewRejectsBadCredentials(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, cred := range map[string]Credential{
		"P-384 key":        PrivateKeyJWT{ClientID: "billing", Key: p384},
		"no client id":     PrivateKeyJWT{Key: p384},
		"no subject token": SubjectToken{},
		"file and command": SubjectToken{File: "/token", Command: []string{"/bin/true"}},
		"empty command":    SubjectToken{Command: []string{""}},
	} {
		if _, err := New(Config{Issuer: &IssuerClient{}, Credential: cred}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Callers asking for the same audiences at once share one request; callers
// asking for many different audiences never have more than a few in flight.
func TestTokenRequestsAreSharedAndBounded(t *testing.T) {
	f := newFixture(t)
	var inFlight, peak, total atomic.Int32
	hook := func() func() {
		n := inFlight.Add(1)
		total.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(50 * time.Millisecond)
		return func() { inFlight.Add(-1) }
	}
	f.onToken.Store(&hook)
	ctx := f.ctx(t)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.agent.token(ctx, []string{"orders"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := total.Load(); n != 1 {
		t.Errorf("20 callers for one audience made %d requests, want 1", n)
	}

	total.Store(0)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The issuer refuses these audiences; only the load matters here.
			_, _ = f.agent.token(ctx, []string{fmt.Sprintf("aud-%d", i)})
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > maxConcurrentFetches {
		t.Errorf("peak of %d concurrent requests, want at most %d", p, maxConcurrentFetches)
	}
	if n := total.Load(); n != 12 {
		t.Errorf("%d requests for 12 audiences, want 12", n)
	}

	// A caller that gives up does not fail the others waiting on its request.
	short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := f.agent.token(ctx, []string{"payments"}); done <- err }()
	if _, err := f.agent.token(short, []string{"payments"}); status.Code(err) != codes.DeadlineExceeded {
		t.Errorf("impatient caller: %v, want DeadlineExceeded", err)
	}
	if err := <-done; err != nil {
		t.Errorf("patient caller: %v", err)
	}
}

// The issuer takes a management token for one write only, so the agent
// fetches a new one for every caller instead of reusing it.
func TestManagementTokensAreNotReused(t *testing.T) {
	f := newFixture(t)
	var total atomic.Int32
	hook := func() func() {
		total.Add(1)
		return func() {}
	}
	f.onToken.Store(&hook)
	ctx := f.ctx(t)
	management := []string{f.srv.URL + "/manage"}
	first, err := f.agent.token(ctx, management)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.agent.token(ctx, management)
	if err != nil {
		t.Fatal(err)
	}
	if first.Value == second.Value || total.Load() != 2 {
		t.Errorf("two management tokens took %d requests and are the same: %v", total.Load(), first.Value == second.Value)
	}
	for range 2 {
		if _, err := f.agent.token(ctx, []string{"orders"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := total.Load(); n != 3 {
		t.Errorf("two tokens for orders made %d requests, want 1", n-2)
	}
}
