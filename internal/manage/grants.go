package manage

import (
	"net/http"

	"github.com/PeterSR/spiffex/internal/state"
)

func (s *Server) getGrant(w http.ResponseWriter, r *http.Request, c caller, b *base) {
	name := r.PathValue("name")
	if !b.readsGrant(c, name) {
		writeError(w, notFound("grant", name))
		return
	}
	writeJSON(w, http.StatusOK, b.version, b.state.Grants[name])
}

// putGrant creates or replaces a grant. No escalation (SPEC section 8.2):
// the caller must hold delegate on each scope of the grant, and every
// permission it gives there, in its old form and its new.
func (s *Server) putGrant(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	var g state.Grant
	if err := readBody(w, r, &g); err != nil {
		writeError(w, err)
		return
	}
	ch := &change{action: "put", object: "grants/" + name, own: "grants." + name, answer: &g}
	ch.apply = func(b *base, next *state.State) error {
		if old := b.state.Grants[name]; old != nil {
			if !b.readsGrant(c, name) {
				return errorf(http.StatusConflict, "grant %s exists, and you may not read it", name)
			}
			if perm, scope, ok := b.lacksForGrant(c, old); !ok {
				return forbidden("changing grant %s takes %s on %s, which you do not hold", name, perm, scope)
			}
		}
		// Authorized as written, before anything else is checked: a scope
		// or permission that is not well formed is never held. The limits
		// bound that work.
		if len(g.On) > state.MaxScopesPerGrant || len(g.Can) > 3 {
			return errorf(http.StatusUnprocessableEntity, "a grant gives at most 3 permissions on at most %d scopes", state.MaxScopesPerGrant)
		}
		if perm, scope, ok := b.lacksForGrant(c, &g); !ok {
			return forbidden("grant %s would give or need %s on %s, which you do not hold", name, perm, scope)
		}
		alone := state.Validate(&state.State{Grants: map[string]*state.Grant{name: &g}}, s.cfg.Settings)
		if len(alone.Problems) > 0 {
			return &apiError{status: http.StatusUnprocessableEntity, msg: "the grant is invalid", problems: alone.Problems}
		}
		ch.created = next.Grants[name] == nil
		next.Grants[name] = &g
		return nil
	}
	s.write(w, r, c, ch)
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	ch := &change{action: "delete", object: "grants/" + name, own: "grants." + name}
	ch.apply = func(b *base, next *state.State) error {
		if !b.readsGrant(c, name) {
			return notFound("grant", name)
		}
		if perm, scope, ok := b.lacksForGrant(c, b.state.Grants[name]); !ok {
			return forbidden("removing grant %s takes %s on %s, which you do not hold", name, perm, scope)
		}
		delete(next.Grants, name)
		return nil
	}
	s.write(w, r, c, ch)
}
