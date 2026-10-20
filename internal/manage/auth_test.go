package manage

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/PeterSR/spiffex/internal/keyset"
)

func TestAuthentication(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	now := time.Now()
	claims := func(change func(*jwt.Claims)) jwt.Claims {
		c := jwt.Claims{
			Issuer:   h.url,
			Subject:  "spiffe://example.org/people/alice",
			Audience: jwt.Audience{h.url + "/manage"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
			ID:       "id-1",
		}
		change(&c)
		return c
	}
	stranger, err := newSigner()
	if err != nil {
		t.Fatal(err)
	}
	mintedForOrders, _, err := h.iss.Mint(id("/people/alice"), []string{"orders"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"not a JWT", "nonsense"},
		{"minted for another audience", mintedForOrders},
		{"the management audience with another", h.signed(claims(func(c *jwt.Claims) { c.Audience = append(c.Audience, "orders") }))},
		{"the management audience with a trailing slash", h.signed(claims(func(c *jwt.Claims) { c.Audience = jwt.Audience{h.url + "/manage/"} }))},
		{"meant to live ten minutes", h.signed(claims(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(10 * time.Minute)) }))},
		{"without iat", h.signed(claims(func(c *jwt.Claims) { c.IssuedAt = nil }))},
		{"expired", h.signed(claims(func(c *jwt.Claims) {
			c.IssuedAt, c.Expiry = jwt.NewNumericDate(now.Add(-2*time.Minute)), jwt.NewNumericDate(now.Add(-time.Minute))
		}))},
		{"another issuer", h.signed(claims(func(c *jwt.Claims) { c.Issuer = "https://elsewhere.example.org" }))},
		{"without jti", h.signed(claims(func(c *jwt.Claims) { c.ID = "" }))},
		{"another trust domain", h.signed(claims(func(c *jwt.Claims) { c.Subject = "spiffe://example.com/people/alice" }))},
		{"an identity no origin issues", h.token("/nobody/alice")},
		{"a non-member of a keys origin", h.token("/people/mallory")},
		{"signed by a key the issuer does not publish", signWith(t, stranger, h.keys.Keys()[0].ID, claims(func(*jwt.Claims) {}))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := h.do(http.MethodGet, "/state", tc.token, nil)
			wantStatus(t, a, http.StatusUnauthorized)
			if !strings.HasPrefix(a.header.Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", a.header.Get("WWW-Authenticate"))
			}
		})
	}
	// The same claims, as the issuer signs them, are accepted, with the
	// audience as a string or as a one-element array.
	wantStatus(t, h.do(http.MethodGet, "/state", h.signed(claims(func(*jwt.Claims) {})), nil), http.StatusOK)
	asString := map[string]any{
		"iss": h.url, "sub": "spiffe://example.org/people/alice", "aud": h.url + "/manage",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "id-2",
	}
	wantStatus(t, h.do(http.MethodGet, "/state", h.signed(asString), nil), http.StatusOK)
}

// Removing a member or an origin revokes management access at once, not
// when the caller's token expires.
func TestRemovalRevokesAccess(t *testing.T) {
	h := newHarness(t, dirStore(t), people)
	dave := h.token("/people/dave")
	wantStatus(t, h.do(http.MethodGet, "/state", dave, nil), http.StatusOK)
	wantStatus(t, h.as("/people/alice", http.MethodDelete, "/origins/people/members/dave", nil), http.StatusNoContent)
	wantStatus(t, h.do(http.MethodGet, "/state", dave, nil), http.StatusUnauthorized)

	temp := map[string]any{"provider": "keys", "prefix": "/temp", "members": map[string]any{"t": h.member()}}
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/origins/temp", temp), http.StatusCreated)
	tempToken := h.token("/temp/t")
	wantStatus(t, h.do(http.MethodGet, "/state", tempToken, nil), http.StatusOK)
	wantStatus(t, h.as("/people/alice", http.MethodDelete, "/origins/temp", nil), http.StatusNoContent)
	wantStatus(t, h.do(http.MethodGet, "/state", tempToken, nil), http.StatusUnauthorized)
}

// A token writes once; reading with it again is fine.
func TestReplayedTokenCannotWriteAgain(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	token := h.token("/people/bob")
	wantStatus(t, h.do(http.MethodGet, "/state", token, nil), http.StatusOK)
	wantStatus(t, h.do(http.MethodGet, "/state", token, nil), http.StatusOK)
	origin := map[string]any{"provider": "keys", "prefix": "/team/x"}
	wantStatus(t, h.do(http.MethodPut, "/origins/team-x", token, origin), http.StatusCreated)
	wantStatus(t, h.do(http.MethodPut, "/origins/team-x", token, origin), http.StatusUnauthorized)
	// A refused write does not use the token up: only authorized writes
	// are recorded, so nobody can fill the record with refused ones.
	refused := h.token("/people/bob")
	wantStatus(t, h.do(http.MethodPut, "/origins/elsewhere", refused, map[string]any{"provider": "keys"}), http.StatusForbidden)
	wantStatus(t, h.do(http.MethodPut, "/origins/team-y", refused, keysOrigin("/team/y")), http.StatusCreated)
	wantStatus(t, h.do(http.MethodPut, "/origins/team-z", refused, keysOrigin("/team/z")), http.StatusUnauthorized)
	for range 50 {
		wantStatus(t, h.as("/people/dave", http.MethodPut, "/origins/x", keysOrigin("/x")), http.StatusForbidden)
	}
	if n := len(h.server.replay.seen); n != 2 {
		t.Errorf("%d token IDs recorded, want the 2 that wrote", n)
	}
}

// A full record refuses new tokens until entries expire, rather than forget
// one that could then write again.
func TestReplayCacheRefusesWhenFull(t *testing.T) {
	c := newReplayCache()
	now := time.Now()
	for i := range maxReplayEntries {
		if err := c.use(fmt.Sprint(i), now.Add(time.Minute+time.Duration(i)*time.Millisecond), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.use("new", now.Add(5*time.Minute), now); !errors.Is(err, errReplayFull) {
		t.Errorf("a full record took a new token: %v", err)
	}
	if err := c.use("0", now.Add(time.Minute), now); !errors.Is(err, errReplayed) {
		t.Errorf("a remembered token was taken again: %v", err)
	}
	later := now.Add(time.Minute + time.Millisecond)
	if err := c.use("new", later.Add(5*time.Minute), later); err != nil {
		t.Errorf("the record stayed full after entries expired: %v", err)
	}
}

// Unauthenticated callers, and identities the state no longer issues, are
// turned away without the storage being touched; so are reads.
func TestReadsAndRefusalsDoNotTouchStorage(t *testing.T) {
	counting := &countingStore{Store: fileStore(t)}
	h := newHarness(t, counting, people)
	counting.loads.Store(0)
	wantStatus(t, h.do(http.MethodPut, "/origins/x", "", keysOrigin("/x")), http.StatusUnauthorized)
	wantStatus(t, h.as("/people/mallory", http.MethodPut, "/origins/x", keysOrigin("/x")), http.StatusUnauthorized)
	wantStatus(t, h.as("/people/alice", http.MethodGet, "/state", nil), http.StatusOK)
	wantStatus(t, h.as("/people/alice", http.MethodGet, "/origins/people", nil), http.StatusOK)
	if n := counting.loads.Load(); n != 0 {
		t.Errorf("the storage was read %d times", n)
	}
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/origins/x", keysOrigin("/x")), http.StatusCreated)
	if n := counting.loads.Load(); n != 1 {
		t.Errorf("a write read the storage %d times, want once", n)
	}
}

func TestCallersAreRateLimited(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	h.server.limiter = newCallerLimiter(1, 3)
	for range 3 {
		wantStatus(t, h.as("/people/bob", http.MethodGet, "/state", nil), http.StatusOK)
	}
	a := h.as("/people/bob", http.MethodGet, "/state", nil)
	wantStatus(t, a, http.StatusTooManyRequests)
	if a.header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	wantStatus(t, h.as("/people/carol", http.MethodGet, "/state", nil), http.StatusOK)
}

// With no signing key the issuer mints no management token and publishes no
// key to check one against, so the API admits nobody until a key is back:
// a token signed before the last key was removed is refused as well. Reads
// and writes of the stored state through the files go on as before.
func TestNoSigningKeyAdmitsNobody(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	token := h.token("/people/alice")
	wantStatus(t, h.do(http.MethodGet, "/state", token, nil), http.StatusOK)

	h.source.set.Store(keyset.EmptySet())
	wantStatus(t, h.do(http.MethodGet, "/state", token, nil), http.StatusUnauthorized)
	if _, _, err := h.iss.Mint(id("/people/alice"), []string{h.iss.ManagementEndpoint()}); err == nil {
		t.Error("the issuer minted a management token without a key")
	}

	h.source.set.Store(h.keys)
	wantStatus(t, h.do(http.MethodGet, "/state", h.token("/people/alice"), nil), http.StatusOK)
}
