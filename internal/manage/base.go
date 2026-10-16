package manage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/PeterSR/spiffex/internal/state"
)

// base is one version of the state, valid, which requests are authorized
// against and writes build on. Its state is shared and must not be
// changed; clone it first.
type base struct {
	version   string
	state     *state.State
	origins   map[string]*state.Expanded
	grants    []state.ParsedGrant
	overrides []string
}

// inService is the state this process serves, which reads are answered
// from and callers are checked against before anything touches storage.
// It is the latest version a reload or a write put in service here.
func (s *Server) inService() *base {
	v := s.cfg.Policy.Current()
	return &base{version: v.Version, state: v.Document(), origins: v.Expanded(), grants: v.Grants(), overrides: v.Overrides()}
}

var errStateUnusable = &apiError{status: http.StatusServiceUnavailable,
	msg: "the stored state cannot be read or is invalid; it must be repaired in its storage"}

// load reads the stored state for a write. A state that cannot be read, or
// is invalid under the issuer's settings, cannot be authorized against, so
// writes are refused until it is repaired in storage. Writes hold writeMu,
// so one load and one validation of a version run at a time, and the last
// validated version is kept for the next write.
func (s *Server) load(ctx context.Context) (*base, error) {
	snap, err := s.cfg.Store.Load(ctx)
	if err != nil {
		s.cfg.Logger.Error("the management API cannot read the state", "state", s.cfg.Store.String(), "error", err)
		return nil, errStateUnusable
	}
	if snap.Problem != nil {
		s.cfg.Logger.Error("the management API found the stored state invalid", "version", snap.Version, "error", snap.Problem)
		return nil, errStateUnusable
	}
	if s.loaded != nil && s.loaded.version == snap.Version {
		return s.loaded, nil
	}
	report := state.Validate(snap.State, s.cfg.Settings)
	if err := report.Err(); err != nil {
		s.cfg.Logger.Error("the management API found the stored state invalid", "version", snap.Version, "error", err)
		return nil, errStateUnusable
	}
	s.loaded = &base{version: snap.Version, state: snap.State, origins: report.Origins, grants: report.Grants, overrides: report.Overrides}
	return s.loaded, nil
}

// issuable reports whether the caller could still be issued its identity
// under this state (SPEC section 8.1).
func (s *Server) issuable(b *base, c caller) bool {
	return state.Issuable(b.origins, s.cfg.Settings.TrustDomain, c.id)
}

// holds reports whether the caller holds perm on path.
func (b *base) holds(c caller, perm, path string) bool {
	return state.Holds(b.grants, c.id, perm, path)
}

// readsOrigin reports whether the caller may read the origin: read on its
// prefix.
func (b *base) readsOrigin(c caller, name string) bool {
	e := b.origins[name]
	return e != nil && b.holds(c, state.PermRead, e.Prefix)
}

// readsGrant reports whether the caller may read the grant: read on each
// of its scopes.
func (b *base) readsGrant(c caller, name string) bool {
	g := b.state.Grants[name]
	if g == nil {
		return false
	}
	for _, scope := range g.On {
		if !b.holds(c, state.PermRead, scope) {
			return false
		}
	}
	return true
}

// lacksForGrant returns a permission and scope the caller lacks to create,
// change or remove a grant: delegate on each of its scopes, and every
// permission it gives on each of them (SPEC section 8.2). ok is true when
// it lacks none.
func (b *base) lacksForGrant(c caller, g *state.Grant) (perm, scope string, ok bool) {
	for _, scope := range g.On {
		if !b.holds(c, state.PermDelegate, scope) {
			return state.PermDelegate, scope, false
		}
		for _, perm := range g.Can {
			if !b.holds(c, perm, scope) {
				return perm, scope, false
			}
		}
	}
	return "", "", true
}

// clone returns a deep copy of the state, for a write to change.
func clone(st *state.State) (*state.State, error) {
	data, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	var out state.State
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("copying the state: %w", err)
	}
	if out.Origins == nil {
		out.Origins = map[string]*state.Origin{}
	}
	if out.Providers == nil {
		out.Providers = map[string]*state.Provider{}
	}
	if out.Grants == nil {
		out.Grants = map[string]*state.Grant{}
	}
	return &out, nil
}
