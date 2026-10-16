// Package manage serves the management API (SPEC section 8): reading and
// changing the issuer's state while it runs, for SPIFFE identities that
// hold grants.
//
// Every request is authenticated with a JWT-SVID the issuer itself signed
// for the management endpoint, and authorized against the stored state as
// it is at that moment. A write reads the stored state, changes it,
// validates the result as a whole, and stores it with compare-and-swap; it
// then puts the new state in service in this process at once, while other
// processes serving the issuer URL take it up at their next reload.
package manage

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// MaxBody bounds a request body (SPEC section 8.3).
const MaxBody = 1 << 20

// The default limits on each caller's requests.
const (
	defaultRequestsPerSecond = 5
	defaultRequestBurst      = 30
)

// maxWriteAttempts bounds how often a write without If-Match starts over
// because the stored state changed under it.
const maxWriteAttempts = 5

// KeySource supplies the issuer's published signing keys, which management
// tokens must verify against. keyset.Watcher implements it.
type KeySource interface {
	Current() (set *keyset.Set, sequence uint64, changed <-chan struct{})
}

// Policy holds the state this process serves. policy.Policy implements it.
type Policy interface {
	Current() *policy.View
	// Advance puts snap in service if from is the version in service, and
	// reports whether it did.
	Advance(from string, snap *store.Snapshot) (bool, error)
}

// Config configures a Server.
type Config struct {
	// Settings are what validation needs: the issuer URL, the trust domain,
	// and the files and verifiers the state may name.
	Settings state.Settings
	Store    store.Store
	Keys     KeySource
	// Policy serves the state that reads are answered from, and is given
	// every state the API stores.
	Policy Policy
	Logger *slog.Logger
	// RequestsPerSecond and RequestBurst limit each caller: so many
	// requests a second on average, and so many in a row after a quiet
	// spell. Zero means 5 and 30.
	RequestsPerSecond, RequestBurst float64
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Server serves the management API. Create it with New.
type Server struct {
	cfg      Config
	audience string
	mux      *http.ServeMux
	replay   *replayCache
	limiter  *callerLimiter
	// writeMu serialises writes in this process, so they do not make each
	// other start over; compare-and-swap still guards against other
	// processes.
	writeMu sync.Mutex
	// loaded is the stored state the last write read, validated. It is
	// guarded by writeMu.
	loaded *base
}

// New returns a Server for the issuer in cfg.Settings.
func New(cfg Config) (*Server, error) {
	if err := cfg.Settings.Check(); err != nil {
		return nil, err
	}
	if cfg.Store == nil || cfg.Keys == nil || cfg.Policy == nil {
		return nil, errors.New("a store, a key source and a policy are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = defaultRequestsPerSecond
	}
	if cfg.RequestBurst <= 0 {
		cfg.RequestBurst = defaultRequestBurst
	}
	u, err := url.Parse(cfg.Settings.ManagementEndpoint())
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, audience: cfg.Settings.ManagementEndpoint(), replay: newReplayCache(),
		limiter: newCallerLimiter(cfg.RequestsPerSecond, cfg.RequestBurst)}
	s.routes(u.Path)
	return s, nil
}

// ServeHTTP implements http.Handler. A path that is not in its clean form
// is not found rather than redirected, so that a name such as .. can never
// lead to another object.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != path.Clean(r.URL.Path) {
		writeError(w, errorf(http.StatusNotFound, "no such endpoint"))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes(prefix string) {
	mux := http.NewServeMux()
	handle := func(method, path string, h func(http.ResponseWriter, *http.Request, caller, *base)) {
		mux.HandleFunc(method+" "+prefix+path, s.authenticated(h))
	}
	handle("GET", "/state", s.getState)
	handle("POST", "/check", s.check)
	handle("GET", "/origins/{name}", s.getOrigin)
	handle("PUT", "/origins/{name}", s.putOrigin)
	handle("DELETE", "/origins/{name}", s.deleteOrigin)
	handle("PUT", "/origins/{name}/members/{member}", s.putMember)
	handle("DELETE", "/origins/{name}/members/{member}", s.deleteMember)
	handle("GET", "/providers/{name}", s.getProvider)
	handle("PUT", "/providers/{name}", s.putProvider)
	handle("DELETE", "/providers/{name}", s.deleteProvider)
	handle("GET", "/grants/{name}", s.getGrant)
	handle("PUT", "/grants/{name}", s.putGrant)
	handle("DELETE", "/grants/{name}", s.deleteGrant)
	mux.HandleFunc(prefix+"/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, &apiError{status: http.StatusNotFound, msg: "no such endpoint"})
	})
	s.mux = mux
}
