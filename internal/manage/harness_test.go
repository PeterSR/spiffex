package manage

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

// verifierCommand is the one exec verifier the test issuer has installed.
// It is never run: nothing here exchanges a proof with it.
const verifierCommand = "/opt/spiffex/verifier"

type staticKeys struct{ set *keyset.Set }

func (k staticKeys) Current() (*keyset.Set, uint64, <-chan struct{}) { return k.set, 1, nil }

// syncBuffer is a log destination tests can read while the server writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// harness is an issuer with the management API, over TLS, on a state in a
// store.
type harness struct {
	t      *testing.T
	url    string
	srv    *httptest.Server
	iss    *issuer.Issuer
	server *Server
	store  store.Store
	policy *policy.Policy
	keys   *keyset.Set
	logs   *syncBuffer
	// memberKey is the private key of every member of every keys origin
	// the harness writes.
	memberKey *ecdsa.PrivateKey
}

// stateFunc writes the initial state document, given the issuer URL and a
// public key in PEM, quoted as a JSON string.
type stateFunc func(issuerURL, pemKey string) string

func newHarness(t *testing.T, s store.Store, initial stateFunc) *harness {
	t.Helper()
	keysDir := t.TempDir()
	if _, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	set, err := keyset.LoadDir(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	memberKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h := &harness{t: t, url: srv.URL, srv: srv, store: s, keys: set, logs: &syncBuffer{}, memberKey: memberKey}

	settings := state.DefaultSettings(srv.URL, td)
	settings.Verifiers = [][]string{{verifierCommand}}
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.policy = policy.New(policy.Options{Settings: settings, Logger: logger})

	if initial != nil {
		st, err := state.ParseState([]byte(initial(srv.URL, h.pemKey(&memberKey.PublicKey))))
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Validate(st, settings).Err(); err != nil {
			t.Fatalf("the initial state is invalid:\n%v", err)
		}
		if _, err := s.Write(context.Background(), st, store.Absent); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.policy.Apply(snap); err != nil {
		t.Fatal(err)
	}
	h.server, err = New(Config{Settings: settings, Store: s, Keys: staticKeys{set}, Policy: h.policy, Logger: logger,
		RequestsPerSecond: 1000, RequestBurst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	h.iss, err = issuer.New(issuer.Config{
		URL:         srv.URL,
		TrustDomain: td,
		Keys:        staticKeys{set},
		Policy:      h.policy,
		Management:  h.server,
		Logger:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h.iss.Handler()
	return h
}

func (h *harness) pemKey(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		h.t.Fatal(err)
	}
	quoted, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	return string(quoted)
}

// member is a member whose key is the harness's member key, as a request
// body.
func (h *harness) member() map[string]any {
	return map[string]any{"keys": []json.RawMessage{json.RawMessage(h.pemKey(&h.memberKey.PublicKey))}}
}

func newSigner() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// id returns the SPIFFE ID of a path in the trust domain.
func id(path string) spiffeid.ID { return spiffeid.RequireFromPath(td, path) }

// token mints a management token for the identity with the issuer, as the
// token endpoint would.
func (h *harness) token(path string) string {
	h.t.Helper()
	token, _, err := h.iss.Mint(id(path), []string{h.iss.ManagementEndpoint()})
	if err != nil {
		h.t.Fatal(err)
	}
	return token
}

// signed signs claims with the issuer's own key, for tokens the issuer would
// never mint.
func (h *harness) signed(claims any) string {
	h.t.Helper()
	return signWith(h.t, h.keys.Keys()[0].Signer, h.keys.Keys()[0].ID, claims)
}

func signWith(t *testing.T, key any, kid string, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// answer is a response from the management API.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (a answer) etag() string { return a.header.Get("ETag") }

func (a answer) errorBody(t *testing.T) ErrorBody {
	t.Helper()
	var e ErrorBody
	if err := json.Unmarshal(a.body, &e); err != nil {
		t.Fatalf("error body %q: %v", a.body, err)
	}
	return e
}

// do sends a request with token to a path under /manage. A body that is a
// string is sent as it is; anything else is encoded as JSON.
func (h *harness) do(method, path, token string, body any, headers ...string) answer {
	h.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.url+"/manage"+path, r)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: data}
}

// as sends a request as the identity at path, with a fresh token.
func (h *harness) as(path, method, target string, body any, headers ...string) answer {
	h.t.Helper()
	return h.do(method, target, h.token(path), body, headers...)
}

func wantStatus(t *testing.T, a answer, status int) {
	t.Helper()
	if a.status != status {
		t.Fatalf("status %d, want %d; body: %s", a.status, status, a.body)
	}
}

// stored loads the stored state.
func (h *harness) stored() *store.Snapshot {
	h.t.Helper()
	snap, err := h.store.Load(context.Background())
	if err != nil || snap.Problem != nil {
		h.t.Fatalf("loading the state: %v %v", err, snap.Problem)
	}
	return snap
}

// fileStore, dirStore and configMapStore are the three forms the state is
// kept in; every behaviour is tested on at least one, and the basics on all.
func fileStore(t *testing.T) store.Store {
	return &store.File{Path: filepath.Join(t.TempDir(), "state.yaml")}
}

func dirStore(t *testing.T) store.Store {
	return &store.Dir{Path: filepath.Join(t.TempDir(), "state")}
}

func configMapStore(t *testing.T) store.Store {
	t.Helper()
	api := &fakeAPIServer{objects: map[string]map[string]any{}}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &store.ConfigMap{Namespace: "spiffex", Name: "spiffex-state", APIServer: srv.URL, TokenFile: token, CAFile: ca}
}

// fakeAPIServer serves ConfigMaps in one namespace as the Kubernetes API
// does: a new resourceVersion on every write, and 409 for an update of a
// stale version or a create of something that exists.
type fakeAPIServer struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	next    int
}

func (f *fakeAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer sa-token" {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const collection = "/api/v1/namespaces/spiffex/configmaps"
	name, isObject := strings.CutPrefix(r.URL.Path, collection+"/")
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	var obj map[string]any
	if r.Method != http.MethodGet {
		_ = json.NewDecoder(r.Body).Decode(&obj)
	}
	switch {
	case r.Method == http.MethodGet && isObject:
		if current, ok := f.objects[name]; ok {
			reply(http.StatusOK, current)
			return
		}
		reply(http.StatusNotFound, map[string]string{"message": "not found"})
	case r.Method == http.MethodPost && r.URL.Path == collection:
		name := obj["metadata"].(map[string]any)["name"].(string)
		if _, exists := f.objects[name]; exists {
			reply(http.StatusConflict, map[string]string{"message": "already exists"})
			return
		}
		f.put(name, obj)
		reply(http.StatusCreated, obj)
	case r.Method == http.MethodPut && isObject:
		current, ok := f.objects[name]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		if obj["metadata"].(map[string]any)["resourceVersion"] != current["metadata"].(map[string]any)["resourceVersion"] {
			reply(http.StatusConflict, map[string]string{"message": "the object has been modified"})
			return
		}
		f.put(name, obj)
		reply(http.StatusOK, obj)
	default:
		reply(http.StatusMethodNotAllowed, map[string]string{"message": "no"})
	}
}

func (f *fakeAPIServer) put(name string, obj map[string]any) {
	f.next++
	obj["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.next)
	f.objects[name] = obj
}

// countingStore counts the loads of the store it wraps.
type countingStore struct {
	store.Store
	loads atomic.Int32
}

func (c *countingStore) Load(ctx context.Context) (*store.Snapshot, error) {
	c.loads.Add(1)
	return c.Store.Load(ctx)
}
