package manage

import (
	"net/http"
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// Headers that say where a provider comes from (SPEC section 8.3).
const (
	// ProviderSourceHeader is state or shipped on GET of a provider.
	ProviderSourceHeader = "Spiffex-Provider-Source"
	// OverridesHeader names the providers in the state that take the place
	// of shipped ones, separated by commas, on GET of the state or of such
	// a provider.
	OverridesHeader = "Spiffex-Overrides"
)

func forbidden(format string, args ...any) *apiError {
	return errorf(http.StatusForbidden, format, args...)
}

func notFound(kind, name string) *apiError {
	return errorf(http.StatusNotFound, "there is no %s %s that you may read", kind, name)
}

// getState answers with the providers, and the origins and grants the
// caller may read.
func (s *Server) getState(w http.ResponseWriter, _ *http.Request, c caller, b *base) {
	out := state.State{Providers: b.state.Providers, Origins: map[string]*state.Origin{}, Grants: map[string]*state.Grant{}}
	for name, o := range b.state.Origins {
		if b.readsOrigin(c, name) {
			out.Origins[name] = o
		}
	}
	for name, g := range b.state.Grants {
		if b.readsGrant(c, name) {
			out.Grants[name] = g
		}
	}
	if len(b.overrides) > 0 {
		w.Header().Set(OverridesHeader, strings.Join(b.overrides, ", "))
	}
	writeJSON(w, http.StatusOK, b.version, out)
}

// check validates a proposed state document without storing it. It takes
// read on /, since its answer can describe any part of the state. Its work
// is bounded by the limits validation checks first: the size of the
// document, and the number of grants and their scopes.
func (s *Server) check(w http.ResponseWriter, r *http.Request, c caller, b *base) {
	if !b.holds(c, state.PermRead, "/") {
		writeError(w, forbidden("checking a state takes read on /"))
		return
	}
	var proposed state.State
	if err := readBody(w, r, &proposed); err != nil {
		writeError(w, err)
		return
	}
	report := state.Validate(&proposed, s.cfg.Settings)
	writeJSON(w, http.StatusOK, noVersion, CheckResult{
		Valid:     len(report.Problems) == 0,
		Problems:  toProblems(report.Problems),
		Overrides: report.Overrides,
	})
}

// getProvider answers with a provider of the state, or else a shipped one,
// and says which it is.
func (s *Server) getProvider(w http.ResponseWriter, r *http.Request, _ caller, b *base) {
	name := r.PathValue("name")
	p := b.state.Providers[name]
	switch {
	case p != nil:
		w.Header().Set(ProviderSourceHeader, "state")
	default:
		var ok bool
		if p, ok = state.Shipped(name); !ok {
			writeError(w, notFound("provider", name))
			return
		}
		w.Header().Set(ProviderSourceHeader, "shipped")
	}
	// Every override, whichever provider was asked for (SPEC section 8.4).
	if len(b.overrides) > 0 {
		w.Header().Set(OverridesHeader, strings.Join(b.overrides, ", "))
	}
	writeJSON(w, http.StatusOK, b.version, p)
}

func (s *Server) putProvider(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	var p state.Provider
	if err := readBody(w, r, &p); err != nil {
		writeError(w, err)
		return
	}
	ch := &change{action: "put", object: "providers/" + name, own: "providers." + name, answer: &p}
	ch.apply = func(b *base, next *state.State) error {
		if !b.holds(c, state.PermWrite, "/") {
			return forbidden("changing providers takes write on /")
		}
		ch.created = next.Providers[name] == nil
		next.Providers[name] = &p
		return nil
	}
	s.write(w, r, c, ch)
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	ch := &change{action: "delete", object: "providers/" + name, own: "providers." + name}
	ch.apply = func(b *base, next *state.State) error {
		if next.Providers[name] == nil {
			return errorf(http.StatusNotFound, "there is no provider %s in the state", name)
		}
		if !b.holds(c, state.PermWrite, "/") {
			return forbidden("changing providers takes write on /")
		}
		delete(next.Providers, name)
		return nil
	}
	s.write(w, r, c, ch)
}
