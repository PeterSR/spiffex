package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// fakeX509Issuer answers discovery, the bundle endpoint and X.509-SVID
// requests, with a lifetime and failures the test chooses. It has no
// authentication: the identity is the last element of the client id.
type fakeX509Issuer struct {
	t         *testing.T
	srv       *httptest.Server
	supported atomic.Bool
	lifetime  atomic.Int64
	// behave, when set, decides how the token endpoint answers a request: ""
	// issues, "down" fails with 503, anything else is that OAuth error.
	behave atomic.Pointer[func(clientID string, attempt int) string]
	// discoveryBody, when set, replaces the discovery document.
	discoveryBody atomic.Pointer[string]
	// notBeforeShift moves every certificate's notBefore, in nanoseconds.
	notBeforeShift atomic.Int64
	// bundleHook runs in the bundle endpoint after it has chosen what to
	// serve.
	bundleHook atomic.Pointer[func()]

	mu       sync.Mutex
	roots    []fakeRoot // published
	signer   fakeRoot
	serial   int64
	attempts map[string]int
	times    map[string][]time.Time
	bodies   []string
	issued   map[string]int
}

func newFakeX509Issuer(t *testing.T, lifetime time.Duration) *fakeX509Issuer {
	t.Helper()
	f := &fakeX509Issuer{t: t, attempts: map[string]int{}, times: map[string][]time.Time{}, issued: map[string]int{}}
	f.supported.Store(true)
	f.lifetime.Store(int64(lifetime))
	f.signer = f.newRoot()
	f.roots = []fakeRoot{f.signer}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if body := f.discoveryBody.Load(); body != nil {
			_, _ = io.WriteString(w, *body)
			return
		}
		doc := map[string]any{
			"issuer": f.srv.URL, "token_endpoint": f.srv.URL + "/token",
			"spiffe_bundle_endpoint": f.srv.URL + "/bundle", "spiffe_trust_domain": "example.org",
		}
		if f.supported.Load() {
			doc["spiffex_x509_svid_supported"] = true
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/bundle", f.serveBundle)
	mux.HandleFunc("/token", f.serveToken)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeX509Issuer) newRoot() fakeRoot {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(f.serial), Subject: pkix.Name{CommonName: fmt.Sprintf("root %d", f.serial)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		f.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		f.t.Fatal(err)
	}
	return fakeRoot{cert, key}
}

// rotate publishes a new root and signs with it from now on; the old root
// stays published.
func (f *fakeX509Issuer) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signer = f.newRoot()
	f.roots = append(f.roots, f.signer)
}

// publish adds a root to the bundle without signing with it.
func (f *fakeX509Issuer) publish() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots = append(f.roots, f.newRoot())
}

// retire removes the root published last, which does not sign.
func (f *fakeX509Issuer) retire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots = f.roots[:len(f.roots)-1]
}

func (f *fakeX509Issuer) rootCerts() []*x509.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*x509.Certificate
	for _, r := range f.roots {
		out = append(out, r.cert)
	}
	return out
}

func (f *fakeX509Issuer) serveBundle(w http.ResponseWriter, _ *http.Request) {
	jwtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Error(err)
	}
	b := spiffebundle.New(td)
	b.AddJWTAuthority("k1", jwtKey.Public())
	b.SetX509Authorities(f.rootCerts())
	if hook := f.bundleHook.Load(); hook != nil {
		(*hook)()
	}
	if !f.supported.Load() {
		b.SetX509Authorities(nil)
	}
	data, err := b.Marshal()
	if err != nil {
		f.t.Error(err)
	}
	_, _ = w.Write(data)
}

func (f *fakeX509Issuer) serveToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := r.ParseForm(); err != nil {
		f.t.Error(err)
	}
	// A body parsed again below, so keep the raw text for the leak checks.
	r.Body = io.NopCloser(bytes.NewReader(body))
	form, _ := url.ParseQuery(string(body))
	clientID := form.Get("client_id")

	f.mu.Lock()
	f.attempts[clientID]++
	attempt := f.attempts[clientID]
	f.times[clientID] = append(f.times[clientID], time.Now())
	f.bodies = append(f.bodies, string(body))
	signer := f.signer
	f.mu.Unlock()

	if behave := f.behave.Load(); behave != nil {
		switch outcome := (*behave)(clientID, attempt); outcome {
		case "":
		case "down":
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": outcome, "error_description": "the origin does not issue X.509-SVIDs"})
			return
		}
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(form.Get("csr"))
	if err != nil {
		f.t.Error(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		f.t.Errorf("csr: %v", err)
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	id := "spiffe://example.org/" + path.Base(clientID)
	u, _ := url.Parse(id)
	life := time.Duration(f.lifetime.Load())
	f.mu.Lock()
	f.serial++
	serial := f.serial
	f.issued[clientID]++
	f.mu.Unlock()
	// Whole seconds, and exactly the lifetime asked for: the clock has the
	// certificate start up to a second ago.
	notBefore := time.Now().Truncate(time.Second).Add(time.Duration(f.notBeforeShift.Load()))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notBefore.Add(life),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, csr.PublicKey, signer.key)
	if err != nil {
		f.t.Error(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      base64.RawURLEncoding.EncodeToString(der),
		"issued_token_type": tokenTypeX509SVID, "token_type": "N_A", "expires_in": int(life.Seconds()), "spiffe_id": id,
	})
}

func (f *fakeX509Issuer) count(clientID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts[clientID]
}

func (f *fakeX509Issuer) issuedCount(clientID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued[clientID]
}

func (f *fakeX509Issuer) setBehaviour(fn func(clientID string, attempt int) string) {
	f.behave.Store(&fn)
}

// syncBuffer is a log destination safe for the agent's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type x509Rig struct {
	fake  *fakeX509Issuer
	agent *Agent
	addr  string
	sock  string
	logs  *syncBuffer
	ctx   context.Context
	conn  *grpc.ClientConn
}

// newX509Rig runs an agent for the workload clientID against the fake issuer,
// with retry waits short enough for a test.
func newX509Rig(t *testing.T, fake *fakeX509Issuer, clientID string) *x509Rig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	logs := &syncBuffer{}
	client, err := Discover(ctx, fake.srv.URL, spiffeid.TrustDomain{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Issuer: client, Credential: PrivateKeyJWT{ClientID: clientID, Key: key}, Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	a.x509.minRetry, a.x509.maxRetry = 20*time.Millisecond, 200*time.Millisecond
	go a.Run(ctx)

	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := a.NewServer()
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &x509Rig{fake: fake, agent: a, addr: "unix://" + sock, sock: sock, logs: logs, ctx: ctx, conn: conn}
}

// svidStream is an open FetchX509SVID stream, read one message at a time.
type svidStream struct {
	t      *testing.T
	stream workload.SpiffeWorkloadAPI_FetchX509SVIDClient
	cancel context.CancelFunc
}

func (r *x509Rig) openSVID(t *testing.T) *svidStream {
	t.Helper()
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(r.ctx, "workload.spiffe.io", "true"))
	t.Cleanup(cancel)
	stream, err := workload.NewSpiffeWorkloadAPIClient(r.conn).FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return &svidStream{t, stream, cancel}
}

// recv returns the next message or error, failing the test if neither comes
// within d.
func (s *svidStream) recv(d time.Duration) (*workload.X509SVIDResponse, error) {
	s.t.Helper()
	type result struct {
		resp *workload.X509SVIDResponse
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := s.stream.Recv()
		got <- result{resp, err}
	}()
	select {
	case r := <-got:
		return r.resp, r.err
	case <-time.After(d):
		s.cancel()
		s.t.Fatalf("nothing received within %s", d)
		return nil, nil
	}
}

func (s *svidStream) mustRecv(d time.Duration) *workload.X509SVIDResponse {
	s.t.Helper()
	resp, err := s.recv(d)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

// expectSilence asserts that no message arrives within d.
func (s *svidStream) expectSilence(d time.Duration) {
	s.t.Helper()
	type result struct {
		resp *workload.X509SVIDResponse
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := s.stream.Recv()
		got <- result{resp, err}
	}()
	select {
	case r := <-got:
		s.t.Fatalf("received a message (error %v), want silence", r.err)
	case <-time.After(d):
	}
}

// parsed is a response decoded the way a workload library does.
func parsed(t *testing.T, resp *workload.X509SVIDResponse) (*x509svid.SVID, []*x509.Certificate) {
	t.Helper()
	if len(resp.Svids) != 1 || len(resp.FederatedBundles) != 0 || len(resp.Crl) != 0 {
		t.Fatalf("response has %d SVIDs, %d federated bundles, %d CRLs", len(resp.Svids), len(resp.FederatedBundles), len(resp.Crl))
	}
	entry := resp.Svids[0]
	svid, err := x509svid.ParseRaw(entry.X509Svid, entry.X509SvidKey)
	if err != nil {
		t.Fatal(err)
	}
	if svid.ID.String() != entry.SpiffeId {
		t.Errorf("entry names %s, certificate %s", entry.SpiffeId, svid.ID)
	}
	roots, err := x509.ParseCertificates(entry.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x509svid.Verify(svid.Certificates, x509bundle.FromX509Authorities(td, roots), x509svid.WithTime(later(time.Now(), svid.Certificates[0].NotBefore))); err != nil {
		t.Errorf("the SVID does not verify against the bundle sent with it: %v", err)
	}
	return svid, roots
}

func sameSVID(a, b *workload.X509SVIDResponse) bool {
	return bytes.Equal(a.Svids[0].X509Svid, b.Svids[0].X509Svid) && bytes.Equal(a.Svids[0].X509SvidKey, b.Svids[0].X509SvidKey)
}

func TestRenewalWindowAndTenth(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(10 * time.Hour)
	if got := renewalTime(nb, na, 0); !got.Equal(nb.Add(4 * time.Hour)) {
		t.Errorf("earliest renewal %s", got)
	}
	if got := renewalTime(nb, na, 0.999999); got.Before(nb.Add(4*time.Hour+59*time.Minute)) || got.After(nb.Add(5*time.Hour)) {
		t.Errorf("latest renewal %s", got)
	}
	m := &x509Material{notBefore: nb, notAfter: na}
	if !m.usable(nb.Add(9*time.Hour - time.Second)) {
		t.Error("an SVID with a tenth and a second of its life left is unusable")
	}
	if m.usable(nb.Add(9 * time.Hour)) {
		t.Error("an SVID with exactly a tenth of its life left is usable")
	}
	if m.usable(na.Add(time.Second)) {
		t.Error("an expired SVID is usable")
	}
}

// Every open stream is sent each renewal, all of them the same certificate
// and key, and a renewal comes at 40 to 50 percent of the lifetime.
func TestRenewalReachesEveryStream(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 5*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	streams := []*svidStream{rig.openSVID(t), rig.openSVID(t), rig.openSVID(t)}

	first := make([]*workload.X509SVIDResponse, len(streams))
	for i, s := range streams {
		first[i] = s.mustRecv(5 * time.Second)
	}
	svid, roots := parsed(t, first[0])
	if svid.ID.String() != "spiffe://example.org/billing" || len(roots) != 1 {
		t.Errorf("first SVID %s with %d roots", svid.ID, len(roots))
	}
	if k, ok := svid.PrivateKey.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("key %T, want P-256", svid.PrivateKey)
	}
	for i := 1; i < len(streams); i++ {
		if !sameSVID(first[0], first[i]) {
			t.Fatalf("stream %d was given another certificate or key", i)
		}
	}

	nb, na := svid.Certificates[0].NotBefore, svid.Certificates[0].NotAfter
	life := na.Sub(nb)
	second := make([]*workload.X509SVIDResponse, len(streams))
	for i, s := range streams {
		second[i] = s.mustRecv(5 * time.Second)
	}
	arrived := time.Now()
	if sameSVID(first[0], second[0]) {
		t.Fatal("the renewal sent the old certificate")
	}
	for i := 1; i < len(streams); i++ {
		if !sameSVID(second[0], second[i]) {
			t.Fatalf("stream %d was given another renewal", i)
		}
	}
	renewed, _ := parsed(t, second[0])
	if renewed.ID != svid.ID {
		t.Errorf("renewal is for %s", renewed.ID)
	}
	if k1, k2 := svid.PrivateKey.(*ecdsa.PrivateKey), renewed.PrivateKey.(*ecdsa.PrivateKey); k1.Equal(k2) {
		t.Error("the renewal reused the key")
	}
	if at := arrived.Sub(nb); at < life*40/100-50*time.Millisecond || at > life*50/100+time.Second {
		t.Errorf("renewal at %s of a %s lifetime, want 40 to 50 percent", at, life)
	}
	if n := fake.issuedCount("workloads/billing"); n < 2 || n > 3 {
		t.Errorf("the issuer issued %d certificates for three streams and one renewal, want 2 or 3", n)
	}
}

// The first request fails while the issuer is down: streams wait, the agent
// retries with growing, jittered waits, and the SVID arrives once it is up.
func TestIssuerOutageAtStartAndBackoff(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 30*time.Second)
	fake.setBehaviour(func(_ string, attempt int) string {
		if attempt <= 6 {
			return "down"
		}
		return ""
	})
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.minRetry, rig.agent.x509.maxRetry = 40*time.Millisecond, 160*time.Millisecond
	s := rig.openSVID(t)
	parsed(t, s.mustRecv(10*time.Second))

	fake.mu.Lock()
	times := slices.Clone(fake.times["workloads/billing"])
	fake.mu.Unlock()
	if len(times) != 7 {
		t.Fatalf("%d requests, want 7", len(times))
	}
	nominal := []time.Duration{40, 80, 160, 160, 160, 160}
	for i := 1; i < len(times); i++ {
		gap, top := times[i].Sub(times[i-1]), nominal[i-1]*time.Millisecond
		if gap < top/2-5*time.Millisecond || gap > top+3*time.Second {
			t.Errorf("wait %d was %s, want at least %s and about %s", i, gap, top/2, top)
		}
	}
}

// With an SVID in hand, an outage only delays the renewal: the stream stays
// open and gets the new one when the issuer is back.
func TestIssuerOutageDuringRenewal(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 5*time.Second)
	var down atomic.Bool
	fake.setBehaviour(func(string, int) string {
		if down.Load() {
			return "down"
		}
		return ""
	})
	rig := newX509Rig(t, fake, "workloads/billing")
	s := rig.openSVID(t)
	first := s.mustRecv(5 * time.Second)
	down.Store(true)
	before := fake.count("workloads/billing")
	time.Sleep(2800 * time.Millisecond) // past the latest renewal, well within the lifetime
	if n := fake.count("workloads/billing"); n < before+3 || n > before+30 {
		t.Errorf("%d attempts while the issuer was down, want a bounded series", n-before)
	}
	down.Store(false)
	second := s.mustRecv(5 * time.Second)
	if sameSVID(first, second) {
		t.Error("the renewal after the outage is the old certificate")
	}
	if !strings.Contains(rig.logs.String(), "fetching an X.509-SVID failed") {
		t.Error("the failures were not logged")
	}
}

// An SVID with under a tenth of its life left is not sent, to streams already
// open or to new ones, however long the issuer stays down.
func TestNeverServesUnderATenth(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 4*time.Second)
	var down atomic.Bool
	fake.setBehaviour(func(string, int) string {
		if down.Load() {
			return "down"
		}
		return ""
	})
	rig := newX509Rig(t, fake, "workloads/billing")
	open := rig.openSVID(t)
	first := open.mustRecv(5 * time.Second)
	svid, _ := parsed(t, first)
	down.Store(true)

	// Halfway through the lifetime a new stream is still given it.
	late := rig.openSVID(t)
	if got := late.mustRecv(5 * time.Second); !sameSVID(first, got) {
		t.Error("a new stream was not given the current SVID")
	}
	na := svid.Certificates[0].NotAfter
	life := na.Sub(svid.Certificates[0].NotBefore)
	time.Sleep(time.Until(na.Add(-life/10)) + 100*time.Millisecond)
	fresh := rig.openSVID(t)
	fresh.expectSilence(500 * time.Millisecond)
	open.expectSilence(100 * time.Millisecond)
}

// A refusal is passed on to every stream and remembered, so a workload that
// retries in a loop does not reach the issuer.
func TestRefusalIsCached(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 30*time.Second)
	var refuse atomic.Bool
	refuse.Store(true)
	fake.setBehaviour(func(string, int) string {
		if refuse.Load() {
			return "invalid_target"
		}
		return ""
	})
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.refusalTTL = 600 * time.Millisecond

	waiting := []*svidStream{rig.openSVID(t), rig.openSVID(t)}
	for _, s := range waiting {
		if _, err := s.recv(5 * time.Second); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "invalid_target") {
			t.Fatalf("first stream: %v, want PermissionDenied naming invalid_target", err)
		}
	}
	for range 20 {
		if _, err := rig.openSVID(t).recv(5 * time.Second); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a later stream: %v, want PermissionDenied", err)
		}
	}
	if n := fake.count("workloads/billing"); n != 1 {
		t.Fatalf("the issuer was asked %d times, want 1", n)
	}

	time.Sleep(700 * time.Millisecond)
	if _, err := rig.openSVID(t).recv(5 * time.Second); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after the TTL: %v, want PermissionDenied from a new request", err)
	}
	if n := fake.count("workloads/billing"); n != 2 {
		t.Fatalf("the issuer was asked %d times after the TTL, want 2", n)
	}

	// The operator fixes the origin; the next request after the TTL succeeds.
	refuse.Store(false)
	time.Sleep(700 * time.Millisecond)
	parsed(t, rig.openSVID(t).mustRecv(5*time.Second))
}

// A refusal of a renewal ends the open streams and withdraws the SVID.
func TestRefusedRenewalEndsStreams(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 4*time.Second)
	var refuse atomic.Bool
	fake.setBehaviour(func(string, int) string {
		if refuse.Load() {
			return "invalid_client"
		}
		return ""
	})
	rig := newX509Rig(t, fake, "workloads/billing")
	s := rig.openSVID(t)
	s.mustRecv(5 * time.Second)
	refuse.Store(true)
	if _, err := s.recv(5 * time.Second); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after a refused renewal: %v, want PermissionDenied", err)
	}
	if _, err := rig.openSVID(t).recv(5 * time.Second); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a new stream: %v, want PermissionDenied", err)
	}
	if !strings.Contains(rig.logs.String(), "the issuer refused an X.509-SVID request") {
		t.Error("the refusal was not logged")
	}
}

// An issuer without a CA, and one that gains or loses it while the agent runs.
func TestX509SupportFollowsDiscovery(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 30*time.Second)
	fake.supported.Store(false)
	rig := newX509Rig(t, fake, "workloads/billing")
	header := metadata.AppendToOutgoingContext(rig.ctx, "workload.spiffe.io", "true")
	api := workload.NewSpiffeWorkloadAPIClient(rig.conn)

	svids, err := api.FetchX509SVID(header, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svids.Recv(); status.Code(err) != codes.Unimplemented {
		t.Errorf("FetchX509SVID: %v, want Unimplemented", err)
	}
	bundles, err := api.FetchX509Bundles(header, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.Recv(); status.Code(err) != codes.Unimplemented {
		t.Errorf("FetchX509Bundles: %v, want Unimplemented", err)
	}
	if fake.count("workloads/billing") != 0 {
		t.Error("the issuer was asked for a certificate it does not issue")
	}
	// The JWT side is unaffected.
	jwtBundles, err := api.FetchJWTBundles(header, &workload.JWTBundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtBundles.Recv(); err != nil {
		t.Errorf("FetchJWTBundles: %v", err)
	}

	fake.supported.Store(true)
	rig.agent.refreshBundle(rig.ctx)
	live := rig.openSVID(t)
	parsed(t, live.mustRecv(5*time.Second))

	fake.supported.Store(false)
	rig.agent.refreshBundle(rig.ctx)
	if _, err := live.recv(5 * time.Second); status.Code(err) != codes.Unimplemented {
		t.Errorf("an open stream after the issuer lost its CA: %v, want Unimplemented", err)
	}
}

// New roots and retired ones reach open streams, with the current SVID
// unchanged, and a CA the agent has not heard of yet does not stop renewal.
func TestBundleRotationReachesStreams(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 5*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	svids := rig.openSVID(t)
	first := svids.mustRecv(5 * time.Second)

	header := metadata.AppendToOutgoingContext(rig.ctx, "workload.spiffe.io", "true")
	bundles, err := workload.NewSpiffeWorkloadAPIClient(rig.conn).FetchX509Bundles(header, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	roots := func() int {
		t.Helper()
		resp, err := bundles.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Bundles) != 1 || len(resp.Crl) != 0 {
			t.Fatalf("bundles keyed %v", resp.Bundles)
		}
		certs, err := x509.ParseCertificates(resp.Bundles["spiffe://example.org"])
		if err != nil {
			t.Fatal(err)
		}
		return len(certs)
	}
	if n := roots(); n != 1 {
		t.Fatalf("%d roots, want 1", n)
	}

	fake.publish()
	rig.agent.refreshBundle(rig.ctx)
	if n := roots(); n != 2 {
		t.Errorf("%d roots after one was published, want 2", n)
	}
	update := svids.mustRecv(5 * time.Second)
	if !sameSVID(first, update) {
		t.Error("a new root replaced the SVID")
	}
	if _, roots := parsed(t, update); len(roots) != 2 {
		t.Errorf("SVID stream has %d roots, want 2", len(roots))
	}

	fake.retire()
	rig.agent.refreshBundle(rig.ctx)
	if n := roots(); n != 1 {
		t.Errorf("%d roots after one was retired, want 1", n)
	}
	if _, roots := parsed(t, svids.mustRecv(5*time.Second)); len(roots) != 1 {
		t.Errorf("SVID stream has %d roots after retirement, want 1", len(roots))
	}

	// The issuer starts signing with a new root. The agent has not refreshed
	// its bundle, so the first certificate fails to verify until it does so.
	fake.rotate()
	// The new root reaches the open stream first, with the old SVID.
	renewed := svids.mustRecv(5 * time.Second)
	if sameSVID(renewed, update) {
		renewed = svids.mustRecv(5 * time.Second)
	}
	svid, bundleRoots := parsed(t, renewed)
	if len(bundleRoots) != 2 {
		t.Errorf("renewal after rotation has %d roots, want 2", len(bundleRoots))
	}
	fake.mu.Lock()
	signer := fake.signer.cert
	fake.mu.Unlock()
	if err := svid.Certificates[0].CheckSignatureFrom(signer); err != nil {
		t.Errorf("the renewal is not signed by the new root: %v", err)
	}
}

// Many streams on one agent share one SVID, and agents for different
// workloads each have their own.
func TestConcurrentStreamsShareAnSVID(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 4*time.Second)
	names := []string{"billing", "orders", "kitchen", "routes"}
	const perWorkload = 12

	type seen struct {
		first, second *workload.X509SVIDResponse
	}
	results := make([][]seen, len(names))
	rigs := make([]*x509Rig, len(names))
	streams := make([][]*svidStream, len(names))
	for i, name := range names {
		rigs[i] = newX509Rig(t, fake, "workloads/"+name)
	}
	for i := range names {
		results[i] = make([]seen, perWorkload)
		for range perWorkload {
			streams[i] = append(streams[i], rigs[i].openSVID(t))
		}
	}
	var wg sync.WaitGroup
	for i := range names {
		for j, s := range streams[i] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a, err := s.recv(10 * time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				b, err := s.recv(10 * time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				results[i][j] = seen{a, b}
			}()
		}
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	keys := map[string]string{}
	for i, name := range names {
		base := results[i][0]
		for j, r := range results[i] {
			if !sameSVID(base.first, r.first) || !sameSVID(base.second, r.second) {
				t.Fatalf("%s: stream %d was given another SVID", name, j)
			}
		}
		svid, _ := parsed(t, base.first)
		if svid.ID.Path() != "/"+name {
			t.Errorf("%s: SPIFFE ID %s", name, svid.ID)
		}
		for _, key := range [][]byte{base.first.Svids[0].X509SvidKey, base.second.Svids[0].X509SvidKey} {
			if other, dup := keys[string(key)]; dup {
				t.Errorf("%s and %s share a key", name, other)
			}
			keys[string(key)] = name
		}
		// A whole-second notBefore can bring the next renewal within a second
		// of this one, so a third certificate is no sign of a stream of its own.
		if n := fake.issuedCount("workloads/" + name); n < 2 || n > 3 {
			t.Errorf("%s: %d certificates issued for %d streams and one renewal, want 2 or 3", name, n, perWorkload)
		}
	}
}

// Closing the last stream stops the renewals; the next stream starts them
// again and is given the certificate that is still good.
func TestRenewalStopsWithTheLastStream(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 4*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.jitter = func() float64 { return 0 }
	s := rig.openSVID(t)
	first := s.mustRecv(5 * time.Second)
	svid, _ := parsed(t, first)
	s.cancel()
	renewAt := renewalTime(svid.Certificates[0].NotBefore, svid.Certificates[0].NotAfter, 0)
	time.Sleep(time.Until(renewAt) + 300*time.Millisecond)
	if n := fake.issuedCount("workloads/billing"); n != 1 {
		t.Fatalf("%d certificates issued with no stream open, want 1", n)
	}
	// It is past the renewal time now, but not the end of the life: the new
	// stream gets the old SVID at once and the renewal when it lands.
	again := rig.openSVID(t)
	if got := again.mustRecv(5 * time.Second); !sameSVID(first, got) {
		t.Error("the new stream was not given the SVID that is still good")
	}
	if sameSVID(first, again.mustRecv(5*time.Second)) {
		t.Error("the renewal was the old certificate")
	}
}

// go-spiffe's own sources work against the agent: the X509Source, a
// one-shot fetch, and both bundle calls.
func TestGoSPIFFEX509(t *testing.T) {
	t.Parallel()
	fake := newFakeX509Issuer(t, 4*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	ctx := rig.ctx

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(rig.addr)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	svid, err := source.GetX509SVID()
	if err != nil {
		t.Fatal(err)
	}
	if svid.ID.String() != "spiffe://example.org/billing" {
		t.Errorf("SPIFFE ID %s", svid.ID)
	}
	bundle, err := source.GetX509BundleForTrustDomain(td)
	if err != nil || len(bundle.X509Authorities()) != 1 {
		t.Errorf("bundle %v, %v", bundle, err)
	}
	if _, _, err := x509svid.Verify(svid.Certificates, source); err != nil {
		t.Errorf("verifying with the source: %v", err)
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(rig.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	one, err := client.FetchX509SVID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !one.Certificates[0].Equal(svid.Certificates[0]) {
		t.Error("a second client was given a different certificate")
	}
	all, err := client.FetchX509Context(ctx)
	if err != nil || len(all.SVIDs) != 1 {
		t.Fatalf("context %v, %v", all, err)
	}
	bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := bundles.GetX509BundleForTrustDomain(td); err != nil || len(b.X509Authorities()) != 1 {
		t.Errorf("FetchX509Bundles: %v, %v", b, err)
	}

	// The source follows the renewal.
	deadline := time.Now().Add(5 * time.Second)
	for {
		now, err := source.GetX509SVID()
		if err != nil {
			t.Fatal(err)
		}
		if !now.Certificates[0].Equal(svid.Certificates[0]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the source never saw the renewal")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Keys exist only in the agent's memory and in what it sends: never in its
// logs, in the requests to the issuer, or in a file.
func TestX509KeysStayInMemory(t *testing.T) {
	// A short path for the process's own working directory and temporary
	// directory, both watched for files.
	cwd, tmp, home := t.TempDir(), t.TempDir(), t.TempDir()
	t.Chdir(cwd)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", home)

	fake := newFakeX509Issuer(t, 3*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	s := rig.openSVID(t)
	var keys [][]byte
	for range 2 { // issuance, then renewal
		resp := s.mustRecv(5 * time.Second)
		keys = append(keys, resp.Svids[0].X509SvidKey)
	}
	rig.agent.refreshBundle(rig.ctx)
	// Also exercise the refusal and outage logging.
	fake.setBehaviour(func(string, int) string { return "down" })
	time.Sleep(300 * time.Millisecond)

	logs := rig.logs.String()
	fake.mu.Lock()
	requests := strings.Join(fake.bodies, "\n")
	fake.mu.Unlock()
	if !strings.Contains(logs, "obtained an X.509-SVID") {
		t.Fatalf("the agent did not log the issuance: %q", logs)
	}
	for i, der := range keys {
		parsedKey, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		d := parsedKey.(*ecdsa.PrivateKey).D
		forms := map[string]string{
			"base64":    base64.StdEncoding.EncodeToString(der),
			"base64url": base64.RawURLEncoding.EncodeToString(der),
			"hex":       hex.EncodeToString(der),
			"pem":       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
			"d hex":     hex.EncodeToString(d.Bytes()),
			"d decimal": d.String(),
			"d base64":  base64.StdEncoding.EncodeToString(d.Bytes()),
		}
		for name, form := range forms {
			if strings.Contains(logs, form) {
				t.Errorf("key %d is in the logs as %s", i, name)
			}
			if strings.Contains(requests, form) {
				t.Errorf("key %d is in a request to the issuer as %s", i, name)
			}
		}
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN"} {
		if strings.Contains(logs, marker) || strings.Contains(requests, marker) {
			t.Errorf("%q appears in the logs or a request", marker)
		}
	}

	for _, dir := range []string{cwd, tmp, home} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("%s holds %d entries after issuance and renewal", dir, len(entries))
		}
	}
	entries, err := os.ReadDir(filepath.Dir(rig.sock))
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(entries); !slices.Equal(names, []string{"agent.sock"}) {
		t.Errorf("the socket directory holds %v, want only the socket", names)
	}
}

func entryNames(entries []os.DirEntry) []string {
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// flakyCredential fails while fail is set, as a subject token file does
// while it is being rotated, and counts the proofs it makes.
type flakyCredential struct {
	inner PrivateKeyJWT
	fail  *atomic.Bool
	calls *atomic.Int32
}

func (c flakyCredential) validate() error { return nil }
func (c flakyCredential) grantParams(u string, now time.Time) (url.Values, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return nil, errors.New("reading the subject token: file is being rotated")
	}
	return c.inner.grantParams(u, now)
}

// Audit phase 3 round 1, H2: a credential failure that heals must not keep
// answering new streams.
func TestCredentialFailureThatHealsRecovers(t *testing.T) {
	fake := newFakeX509Issuer(t, 30*time.Second)
	fake.setBehaviour(func(string, int) string { time.Sleep(50 * time.Millisecond); return "" })
	rig := newX509Rig(t, fake, "workloads/billing")
	var fail atomic.Bool
	var calls atomic.Int32
	fail.Store(true)
	rig.agent.cred = flakyCredential{rig.agent.cred.(PrivateKeyJWT), &fail, &calls}

	if _, err := rig.openSVID(t).recv(5 * time.Second); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("while the credential fails: %v, want FailedPrecondition", err)
	}
	fail.Store(false)
	time.Sleep(200 * time.Millisecond)
	for range 20 {
		s := rig.openSVID(t)
		resp, err := s.recv(5 * time.Second)
		s.cancel()
		if err == nil {
			parsed(t, resp)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no stream was given an SVID after the credential healed")
}

// H1: an SVID that is due the moment it arrives (this host's clock ahead of
// the issuer's) is renewed at the floor, not in a loop.
func TestSkewedClockDoesNotStormTheIssuer(t *testing.T) {
	fake := newFakeX509Issuer(t, 10*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.now = func() time.Time { return time.Now().Add(5500 * time.Millisecond) }
	s := rig.openSVID(t)
	s.mustRecv(5 * time.Second)
	time.Sleep(1500 * time.Millisecond)
	if n := fake.issuedCount("workloads/billing"); n > 3 {
		t.Fatalf("%d certificates in 1.5 s with a 10 s lifetime, want at most 3", n)
	}
	if !strings.Contains(rig.logs.String(), "disagree") {
		t.Error("the clock skew was not logged")
	}
}

func TestScheduleRenewal(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(time.Hour)

	at, skewed := scheduleRenewal(nb, na, nb.Add(30*time.Second), 0)
	if skewed || at.Before(nb.Add(24*time.Minute)) || at.After(nb.Add(24*time.Minute+30*time.Second)) {
		t.Errorf("a normal SVID: renew at %s, skewed %v", at.Sub(nb), skewed)
	}
	// Received after its own renewal window: the floor, 30 s for an hour.
	received := nb.Add(50 * time.Minute)
	at, skewed = scheduleRenewal(nb, na, received, 0.5)
	if !skewed || at.Sub(received) != 30*time.Second {
		t.Errorf("a late SVID: wait %s, skewed %v, want 30s and skewed", at.Sub(received), skewed)
	}
	// A short lifetime has a floor of a tenth of it, and never zero.
	at, _ = scheduleRenewal(nb, nb.Add(10*time.Second), nb.Add(9*time.Second), 0)
	if at.Sub(nb.Add(9*time.Second)) != time.Second {
		t.Errorf("a short SVID: wait %s, want 1s", at.Sub(nb.Add(9*time.Second)))
	}
	// A clock behind the issuer's: not yet valid is skew too.
	if _, skewed = scheduleRenewal(nb.Add(2*time.Minute), nb.Add(time.Hour), nb, 0); !skewed {
		t.Error("an SVID starting two minutes ahead is not reported as skewed")
	}
	// The earlier of the two clocks counts: received late in the window the
	// agent's own measure from receipt is the sooner.
	received = nb.Add(-time.Minute)
	at, _ = scheduleRenewal(nb, na, received, 0)
	if want := received.Add(61 * time.Minute * 40 / 100); !at.Equal(want) {
		t.Errorf("renew at %s, want %s (40 percent of what was left at receipt)", at.Sub(nb), want.Sub(nb))
	}
}

// M1: callers that come and go after the renewal time must not starve the
// renewal, and must not cost an issuer request each.
func TestOneShotCallsDoNotStarveRenewal(t *testing.T) {
	fake := newFakeX509Issuer(t, 6*time.Second)
	fake.setBehaviour(func(string, int) string { time.Sleep(100 * time.Millisecond); return "" })
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.jitter = func() float64 { return 0 }
	var calls atomic.Int32
	var fail atomic.Bool
	rig.agent.cred = flakyCredential{rig.agent.cred.(PrivateKeyJWT), &fail, &calls}

	s := rig.openSVID(t)
	first := s.mustRecv(5 * time.Second)
	svid, _ := parsed(t, first)
	s.cancel()
	leaf := svid.Certificates[0]
	time.Sleep(time.Until(renewalTime(leaf.NotBefore, leaf.NotAfter, 0)) + 200*time.Millisecond)
	tenth := leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 10)
	renewed := false
	for time.Now().Before(tenth.Add(-300 * time.Millisecond)) {
		o := rig.openSVID(t)
		got := o.mustRecv(5 * time.Second)
		o.cancel()
		renewed = renewed || !sameSVID(first, got)
		time.Sleep(20 * time.Millisecond)
	}
	if !renewed {
		t.Error("no renewed SVID reached a one-shot caller before the tenth")
	}
	if n := calls.Load(); n > 3 {
		t.Errorf("the credential was used %d times for one renewal and a crowd of one-shot calls", n)
	}
}

// M1: the backoff after failures belongs to the agent, not to a stream.
func TestFailureBackoffSurvivesStreamChurn(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	fake.setBehaviour(func(string, int) string { return "down" })
	rig := newX509Rig(t, fake, "workloads/billing")
	rig.agent.x509.minRetry, rig.agent.x509.maxRetry = time.Second, time.Minute
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(rig.ctx, "workload.spiffe.io", "true"), 100*time.Millisecond)
		if st, err := workload.NewSpiffeWorkloadAPIClient(rig.conn).FetchX509SVID(ctx, &workload.X509SVIDRequest{}); err == nil {
			_, _ = st.Recv()
		}
		cancel()
	}
	if n := fake.count("workloads/billing"); n > 4 {
		t.Errorf("%d issuer requests in 3 s with a one second minimum retry, want at most 4", n)
	}
}

// M2: an SVID whose anchor left the bundle is not sent with it; the agent
// renews at the floor (2 s of a 20 s life, well before the regular 8 s), and
// the stream is given the pair that verifies.
func TestSVIDWithARetiredAnchorIsNotSent(t *testing.T) {
	fake := newFakeX509Issuer(t, 20*time.Second)
	rig := newX509Rig(t, fake, "workloads/billing")
	s := rig.openSVID(t)
	first := s.mustRecv(5 * time.Second)
	fake.rotate()
	fake.mu.Lock()
	fake.roots = fake.roots[1:]
	fake.mu.Unlock()
	rig.agent.refreshBundle(rig.ctx)

	resp := s.mustRecv(5 * time.Second)
	if sameSVID(first, resp) {
		t.Fatal("the old SVID was sent with a bundle that does not hold its anchor")
	}
	parsed(t, resp) // fails if the pair does not verify
	// A new stream is never given the stale pair either.
	parsed(t, rig.openSVID(t).mustRecv(5*time.Second))
}

// M2: a bundle fetch that began earlier never overwrites a later one.
func TestBundleRefreshesAreSerialized(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	rig := newX509Rig(t, fake, "workloads/billing")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, _ := rig.agent.currentBundle(); b != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no bundle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var slow atomic.Bool
	slow.Store(true)
	hook := func() {
		if slow.CompareAndSwap(true, false) {
			time.Sleep(300 * time.Millisecond)
		}
	}
	fake.bundleHook.Store(&hook)
	done := make(chan struct{})
	go func() {
		rig.agent.refreshBundle(rig.ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // the slow fetch has chosen one root
	fake.publish()
	rig.agent.refreshBundle(rig.ctx)
	<-done
	if b, _ := rig.agent.currentBundle(); len(b.X509Authorities()) != 2 {
		t.Errorf("the agent holds %d roots, want 2: an older fetch overwrote a newer one", len(b.X509Authorities()))
	}
}

// M3: a certificate starting a little ahead of this clock is what the client
// accepts, and what the agent serves.
func TestSVIDStartingAheadOfTheClockIsServed(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	fake.notBeforeShift.Store(int64(45 * time.Second))
	rig := newX509Rig(t, fake, "workloads/billing")
	resp := rig.openSVID(t).mustRecv(5 * time.Second)
	svid, roots := parsed(t, resp) // verifies at the leaf's own notBefore
	if !svid.Certificates[0].NotBefore.After(time.Now()) || len(roots) != 1 {
		t.Errorf("notBefore %s is not ahead of the clock", svid.Certificates[0].NotBefore)
	}
	if !strings.Contains(rig.logs.String(), "disagree") {
		t.Error("the clock skew was not logged")
	}
}

// L2: a reread of discovery that is not this issuer's document changes nothing.
func TestDiscoveryRereadIgnoresOtherDocuments(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	rig := newX509Rig(t, fake, "workloads/billing")
	for _, body := range []string{`{}`, `{"issuer":"https://elsewhere.example","spiffex_x509_svid_supported":false}`} {
		fake.discoveryBody.Store(&body)
		rig.agent.refreshBundle(rig.ctx)
		if !rig.agent.issuer.X509Supported() {
			t.Fatalf("%s withdrew X.509 support", body)
		}
	}
	if !strings.Contains(rig.logs.String(), "rereading the issuer's discovery document failed") {
		t.Error("the refused reread was not logged")
	}
}

// R2-L1: a bundle that flaps between a CA and another (replicas that
// disagree) brings renewals forward, but only at the floor.
func TestFlappingBundleCostsFewIssuances(t *testing.T) {
	fake := newFakeX509Issuer(t, time.Hour)
	rig := newX509Rig(t, fake, "workloads/billing")
	s := rig.openSVID(t)
	parsed(t, s.mustRecv(5*time.Second))
	fake.mu.Lock()
	full := append([]fakeRoot(nil), fake.roots...)
	fake.mu.Unlock()
	go func() {
		for {
			if _, err := s.stream.Recv(); err != nil {
				return
			}
		}
	}()
	for i := range 40 {
		fake.mu.Lock()
		if i%2 == 0 {
			r := fake.newRoot()
			fake.signer = r
			fake.roots = []fakeRoot{r}
		} else {
			fake.roots = append([]fakeRoot(nil), full...)
			fake.signer = full[0]
		}
		fake.mu.Unlock()
		rig.agent.refreshBundle(rig.ctx)
		time.Sleep(25 * time.Millisecond)
	}
	// A one hour lifetime has a floor of 30 s, longer than the flips take: nothing more is issued.
	if n := fake.issuedCount("workloads/billing"); n != 1 {
		t.Errorf("%d certificates for 40 bundle changes, want 1 within the floor", n)
	}
}
