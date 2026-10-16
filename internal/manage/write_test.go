package manage

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/store"
)

var stores = map[string]func(*testing.T) store.Store{
	"file":      fileStore,
	"dir":       dirStore,
	"configmap": configMapStore,
}

// Writes go to the store, are taken up by the issuer in this process at
// once, and are logged with the caller, the object and the new version.
func TestWritesReachTheStoreAndTheIssuer(t *testing.T) {
	for kind, open := range stores {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, open(t), people)
			alice := "/people/alice"
			machines := map[string]any{"provider": "keys", "members": map[string]any{"m1": h.member()}}
			a := h.as(alice, http.MethodPut, "/origins/machines", machines)
			wantStatus(t, a, http.StatusCreated)
			snap := h.stored()
			if a.etag() != `"`+snap.Version+`"` {
				t.Errorf("ETag %s, want the stored version %q", a.etag(), snap.Version)
			}
			if snap.State.Origins["machines"] == nil {
				t.Fatal("the origin was not stored")
			}
			if v := h.policy.Current().Version; v != snap.Version {
				t.Errorf("the issuer serves version %q, want %q", v, snap.Version)
			}
			// The new member gets tokens straight away, without a reload.
			ctx := context.Background()
			client, err := agent.Discover(ctx, h.url, td, h.srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			token, err := client.FetchToken(ctx, agent.PrivateKeyJWT{ClientID: "machines/m1", Key: h.memberKey}, []string{"orders"})
			if err != nil {
				t.Fatalf("the new member got no token: %v", err)
			}
			if token.SPIFFEID.String() != "spiffe://example.org/machines/m1" {
				t.Errorf("issued %s", token.SPIFFEID)
			}
			logs := h.logs.String()
			for _, want := range []string{"caller=spiffe://example.org/people/alice", "object=origins/machines", "version=" + snap.Version} {
				if !strings.Contains(logs, want) {
					t.Errorf("the log lacks %q:\n%s", want, logs)
				}
			}

			wantStatus(t, h.as(alice, http.MethodGet, "/origins/machines", nil), http.StatusOK)
			wantStatus(t, h.as(alice, http.MethodDelete, "/origins/machines", nil), http.StatusNoContent)
			if _, err := client.FetchToken(ctx, agent.PrivateKeyJWT{ClientID: "machines/m1", Key: h.memberKey}, []string{"orders"}); err == nil {
				t.Error("a removed member still gets tokens")
			}
		})
	}
}

func TestETagAndIfMatch(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	alice := "/people/alice"
	read := h.as(alice, http.MethodGet, "/state", nil)
	first := read.etag()
	if first == "" {
		t.Fatal("no ETag on GET /manage/state")
	}
	a := h.as(alice, http.MethodPut, "/origins/one", keysOrigin("/one"), "If-Match", first)
	wantStatus(t, a, http.StatusCreated)
	second := a.etag()
	if second == "" || second == first {
		t.Fatalf("ETag after the write %q, before %q", second, first)
	}
	if got := h.as(alice, http.MethodGet, "/origins/one", nil).etag(); got != second {
		t.Errorf("GET of the origin has ETag %s, want %s", got, second)
	}
	for _, stale := range []string{first, "W/" + second, `"nonsense"`} {
		wantStatus(t, h.as(alice, http.MethodPut, "/origins/two", keysOrigin("/two"), "If-Match", stale), http.StatusPreconditionFailed)
	}
	if h.stored().State.Origins["two"] != nil {
		t.Error("a write with a stale If-Match was stored")
	}
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/two", keysOrigin("/two"), "If-Match", `"other", `+second), http.StatusCreated)
	a = h.as(alice, http.MethodDelete, "/origins/two", nil, "If-Match", "*")
	wantStatus(t, a, http.StatusNoContent)
	if a.etag() == "" {
		t.Error("no ETag on DELETE")
	}
}

// Concurrent writers, in one process or in two sharing the store, all get
// their changes in, unless they asked for a version that is gone.
func TestConcurrentWriters(t *testing.T) {
	for kind, open := range stores {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, open(t), people)
			// A second issuer process on the same store and keys.
			otherPolicy := policy.New(policy.Options{Settings: h.server.cfg.Settings})
			if err := otherPolicy.Apply(h.stored()); err != nil {
				t.Fatal(err)
			}
			other, err := New(Config{
				Settings:          h.server.cfg.Settings,
				Store:             h.store,
				Keys:              h.server.cfg.Keys,
				Policy:            otherPolicy,
				Logger:            h.server.cfg.Logger,
				RequestsPerSecond: 1000,
				RequestBurst:      1000,
			})
			if err != nil {
				t.Fatal(err)
			}
			send := func(s *Server, name string, headers ...string) int {
				req := httptest.NewRequest(http.MethodPut, h.url+"/manage/origins/"+name,
					strings.NewReader(fmt.Sprintf(`{"provider": "keys", "prefix": "/team/%s"}`, name)))
				req.Header.Set("Authorization", "Bearer "+h.token("/people/bob"))
				for i := 0; i+1 < len(headers); i += 2 {
					req.Header.Set(headers[i], headers[i+1])
				}
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, req)
				return rec.Code
			}
			const writers = 8
			var wg sync.WaitGroup
			codes := make([]int, writers)
			for i := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := h.server
					if i%2 == 1 {
						s = other
					}
					codes[i] = send(s, fmt.Sprintf("w%d", i))
				}()
			}
			wg.Wait()
			for i, code := range codes {
				if code != http.StatusCreated {
					t.Errorf("writer %d: %d", i, code)
				}
			}
			if n := len(h.stored().State.Origins); n != 5+writers {
				t.Errorf("%d origins stored, want %d", n, 5+writers)
			}

			version := `"` + h.stored().Version + `"`
			for i := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := h.server
					if i%2 == 1 {
						s = other
					}
					codes[i] = send(s, fmt.Sprintf("c%d", i), "If-Match", version)
				}()
			}
			wg.Wait()
			created := 0
			for i, code := range codes {
				switch code {
				case http.StatusCreated:
					created++
				case http.StatusPreconditionFailed:
				default:
					t.Errorf("conditional writer %d: %d", i, code)
				}
			}
			if created != 1 {
				t.Errorf("%d writers with the same If-Match succeeded, want 1", created)
			}
		})
	}
}

func TestRequestBodies(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	alice := "/people/alice"
	for name, body := range map[string]string{
		"unknown field":   `{"provider": "keys", "colour": "blue"}`,
		"two documents":   `{"provider": "keys"} {}`,
		"not JSON":        `provider: keys`,
		"wrong JSON type": `{"provider": ["keys"]}`,
	} {
		a := h.as(alice, http.MethodPut, "/origins/x", body)
		if a.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, a.status)
		}
	}
	huge := `{"provider": "keys", "prefix": "/` + strings.Repeat("a", MaxBody) + `"}`
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/x", huge), http.StatusRequestEntityTooLarge)
	wantStatus(t, h.as(alice, http.MethodPost, "/check", huge), http.StatusRequestEntityTooLarge)
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/Bad_Name", keysOrigin("/bad")), http.StatusUnprocessableEntity)
	wantStatus(t, h.as(alice, http.MethodGet, "/nothing-here", nil), http.StatusNotFound)
}

// A stored state that does not parse, or is invalid under the issuer's
// settings, cannot be written on top of. Reads keep being answered from the
// state in service.
func TestUnusableStoredState(t *testing.T) {
	s := fileStore(t)
	h := newHarness(t, s, people)
	path := s.(*store.File).Path
	for _, content := range []string{"origins: [", "origins: { x: { provider: missing } }"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		wantStatus(t, h.as("/people/alice", http.MethodGet, "/state", nil), http.StatusOK)
		wantStatus(t, h.as("/people/alice", http.MethodPut, "/origins/x", keysOrigin("/x")), http.StatusServiceUnavailable)
	}
	// A state that is gone is the empty state, in which nobody is issuable.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/origins/x", keysOrigin("/x")), http.StatusUnauthorized)
}

// The first grant can only come through storage; until then the API admits
// nobody.
func TestEmptyStateAdmitsNobody(t *testing.T) {
	h := newHarness(t, fileStore(t), nil)
	a := h.as("/people/alice", http.MethodGet, "/state", nil)
	wantStatus(t, a, http.StatusUnauthorized)
	if v := h.policy.Current().Version; v != store.Absent {
		t.Errorf("version %q", v)
	}
}

func TestIfMatch(t *testing.T) {
	cases := []struct {
		header, version string
		want            bool
	}{
		{`*`, "41", true},
		{`*`, "", false},
		{`"41"`, "41", true},
		{`"40", "41"`, "41", true},
		{`"40"`, "41", false},
		{`W/"41"`, "41", false},
		{`""`, "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPut, "/manage/origins/x", nil)
		r.Header.Set("If-Match", c.header)
		if got := ifMatch(r, c.version); got != c.want {
			t.Errorf("If-Match %s against version %q: %v, want %v", c.header, c.version, got, c.want)
		}
	}
}
