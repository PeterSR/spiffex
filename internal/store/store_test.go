package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/PeterSR/spiffex/internal/state"
)

func publicPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func publicJWK(t *testing.T) json.RawMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := jose.JSONWebKey{Key: &key.PublicKey}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rawString(s string) json.RawMessage {
	data, _ := json.Marshal(s)
	return data
}

// sampleState has one object of each kind, and members in each form the
// tree can hold: PEM keys, a JWK, several JWKs, and keys of both kinds,
// which stay in the origin's file.
func sampleState(t *testing.T) *state.State {
	t.Helper()
	pem1, pem2 := publicPEM(t), publicPEM(t)
	empty := ""
	return &state.State{
		Origins: map[string]*state.Origin{
			"kube": {Provider: "kubernetes", With: map[string]state.Strings{"namespaces": state.List("customer-*", "platform")}},
			"vms": {Provider: "keys", Prefix: "/billing", Name: &empty, Members: map[string]*state.Member{
				"billing": {Keys: []json.RawMessage{rawString(pem1), rawString(pem2)}},
				"orders":  {Keys: []json.RawMessage{publicJWK(t)}},
				"stock":   {Keys: []json.RawMessage{publicJWK(t), publicJWK(t)}},
				"mixed":   {Keys: []json.RawMessage{rawString(publicPEM(t)), publicJWK(t)}},
				"odd":     {Keys: []json.RawMessage{rawString("\n" + publicPEM(t))}},
			}},
		},
		Providers: map[string]*state.Provider{
			"partner": {
				Description: "A partner's identity provider.",
				Params:      map[string]*state.Param{"customer": {Type: state.ParamString, Required: true}},
				Proof: state.Proof{JWT: &state.JWTProof{
					Issuer: "https://idp.partner.example", JWKSURI: "https://idp.partner.example/keys", MaxTokenLifetime: "15m",
				}},
				Match: map[string]state.Strings{"customer": state.One("$customer")},
				Name:  "{sub}",
			},
		},
		Grants: map[string]*state.Grant{
			"operators": {Who: "spiffe://example.org/billing", Can: []string{"read", "write"}, On: []string{"/"}},
		},
	}
}

// encoded is the JSON form of a parsed state, for comparing documents.
func encoded(t *testing.T, st *state.State) string {
	t.Helper()
	c, err := canonical(st)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func load(t *testing.T, s Store) *Snapshot {
	t.Helper()
	snap, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Problem != nil {
		t.Fatalf("the stored state does not parse: %v", snap.Problem)
	}
	return snap
}

// testStoreBasics checks what every store must do: an absent state is
// empty, writes round-trip, and every write is compare-and-swap.
func testStoreBasics(t *testing.T, s Store) {
	ctx := context.Background()
	snap := load(t, s)
	if snap.Version != Absent || len(snap.State.Origins) != 0 {
		t.Fatalf("a missing state loads as version %q with %d origins, want the empty state", snap.Version, len(snap.State.Origins))
	}
	st := sampleState(t)
	if _, err := s.Write(ctx, st, "not-a-version"); !errors.Is(err, ErrConflict) {
		t.Fatalf("writing over a missing state with a version: %v, want ErrConflict", err)
	}
	v1, err := s.Write(ctx, st, Absent)
	if err != nil {
		t.Fatal(err)
	}
	snap = load(t, s)
	if snap.Version != v1 {
		t.Errorf("loaded version %q, want the written %q", snap.Version, v1)
	}
	if got, want := encoded(t, snap.State), encoded(t, st); got != want {
		t.Errorf("round trip changed the document:\ngot  %s\nwant %s", got, want)
	}
	if _, err := s.Write(ctx, st, Absent); !errors.Is(err, ErrConflict) {
		t.Errorf("creating over an existing state: %v, want ErrConflict", err)
	}
	st.Origins["ci"] = &state.Origin{Provider: "keys"}
	v2, err := s.Write(ctx, st, v1)
	if err != nil {
		t.Fatal(err)
	}
	if v2 == v1 {
		t.Error("the version did not change with the content")
	}
	if _, err := s.Write(ctx, st, v1); !errors.Is(err, ErrConflict) {
		t.Errorf("writing with a stale version: %v, want ErrConflict", err)
	}
	if snap := load(t, s); snap.Version != v2 || snap.State.Origins["ci"] == nil {
		t.Errorf("after the second write: version %q, origins %v", snap.Version, snap.State.Origins)
	}
}

// testConcurrentWrites checks that of several writers replacing the same
// version, exactly one succeeds.
func testConcurrentWrites(t *testing.T, s Store) {
	ctx := context.Background()
	base, err := s.Write(ctx, &state.State{}, Absent)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	var wg sync.WaitGroup
	results := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := &state.State{Origins: map[string]*state.Origin{fmt.Sprintf("o%d", i): {Provider: "keys"}}}
			_, err := s.Write(ctx, st, base)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrConflict):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Errorf("%d writers succeeded, want exactly 1", won)
	}
}

func TestFile(t *testing.T) {
	for _, name := range []string{"state.yaml", "state.json"} {
		t.Run(name, func(t *testing.T) {
			testStoreBasics(t, &File{Path: filepath.Join(t.TempDir(), name)})
		})
	}
	t.Run("concurrent writes", func(t *testing.T) {
		testConcurrentWrites(t, &File{Path: filepath.Join(t.TempDir(), "state.yaml")})
	})
}

func TestFileEmptyAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")
	f := &File{Path: path}
	if err := os.WriteFile(path, []byte("\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if snap := load(t, f); snap.Version == Absent || len(snap.State.Origins) != 0 {
		t.Errorf("an empty file: version %q, state %v; want the empty state at a version of its own", snap.Version, snap.State)
	}
	if err := os.WriteFile(path, []byte("origins: { a: { nope: 1 } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := f.Load(context.Background())
	if err != nil || snap.Problem == nil || snap.State != nil || snap.Version == "" {
		t.Errorf("an invalid file: %+v, %v; want a snapshot with a problem and a version", snap, err)
	}
}

func TestWatchSettlesFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.yaml")
	f := &File{Path: path}
	target := &recordingTarget{}
	w := watcher{store: f, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), settle: true, target: target}
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	write("origins: {}\n")
	w.check(ctx)
	if len(target.applied) != 0 {
		t.Fatal("a change was applied on first sight")
	}
	write("origins: { a: { provider: keys } }\n")
	w.check(ctx)
	w.check(ctx)
	if len(target.applied) != 1 {
		t.Fatalf("applied %d versions, want the one that held still", len(target.applied))
	}
	w.check(ctx)
	if len(target.applied) != 1 {
		t.Error("the same version was applied twice")
	}
}

// recordingTarget records what it is given. Its generation can be moved on
// while a load is in flight, as a write through the management API does.
type recordingTarget struct {
	generation uint64
	applied    []string
	// during, when set, runs between reading the generation and reloading.
	during func()
}

func (r *recordingTarget) Generation() uint64 {
	g := r.generation
	if r.during != nil {
		r.during()
		r.during = nil
	}
	return g
}

func (r *recordingTarget) Reload(generation uint64, snap *Snapshot) bool {
	if generation != r.generation {
		return false
	}
	r.applied = append(r.applied, snap.Version)
	r.generation++
	return true
}

// A version read before something else was put in service is offered again
// at the next check rather than forgotten.
func TestWatchOffersAStaleReadAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	f := &File{Path: path}
	if err := os.WriteFile(path, []byte(`{"origins": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target := &recordingTarget{}
	w := watcher{store: f, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), target: target}
	target.during = func() { target.generation++ }
	w.check(context.Background())
	if len(target.applied) != 0 {
		t.Fatal("a stale read was applied")
	}
	w.check(context.Background())
	if len(target.applied) != 1 {
		t.Errorf("the version was not offered again: %v", target.applied)
	}
}
