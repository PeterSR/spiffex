package manage

import (
	"net/http"

	"github.com/PeterSR/spiffex/internal/state"
)

func (s *Server) getOrigin(w http.ResponseWriter, r *http.Request, c caller, b *base) {
	name := r.PathValue("name")
	if !b.readsOrigin(c, name) {
		writeError(w, notFound("origin", name))
		return
	}
	writeJSON(w, http.StatusOK, b.version, b.state.Origins[name])
}

func (s *Server) putOrigin(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	var o state.Origin
	if err := readBody(w, r, &o); err != nil {
		writeError(w, err)
		return
	}
	ch := &change{action: "put", object: "origins/" + name, own: "origins." + name, answer: &o}
	ch.apply = func(b *base, next *state.State) error {
		if err := s.authorizeOrigin(b, c, name, &o); err != nil {
			return err
		}
		ch.created = next.Origins[name] == nil
		next.Origins[name] = &o
		return nil
	}
	s.write(w, r, c, ch)
}

// authorizeOrigin decides whether the caller may make the origin name what
// o says (SPEC section 8.3): write on its old and new prefix, and write on /
// when either form takes proofs through a verifier or tokens for an audience
// other than its origin audience. A conflict with an origin the caller may
// not read is a 409 that names only what is not secret about it.
//
// The permissions that need only names and prefixes are checked first. Only
// a caller who passes them has the origin expanded with its provider, to
// learn its kind and audience, and is told what is wrong with it.
func (s *Server) authorizeOrigin(b *base, c caller, name string, o *state.Origin) error {
	old := b.origins[name]
	if old != nil {
		if !b.readsOrigin(c, name) {
			return errorf(http.StatusConflict, "origin %s exists, and you may not read it", name)
		}
		if !b.holds(c, state.PermWrite, old.Prefix) {
			return forbidden("changing origin %s takes write on its prefix %s", name, old.Prefix)
		}
		if why := needsRoot(old); why != "" && !b.holds(c, state.PermWrite, "/") {
			return forbidden("origin %s %s, so changing it takes write on /", name, why)
		}
	}
	prefix := o.Prefix
	if prefix == "" {
		prefix = "/" + name
	}
	if !b.holds(c, state.PermWrite, prefix) {
		return forbidden("origin %s with prefix %s takes write on that prefix, which you do not hold", name, prefix)
	}
	alone := state.ValidateOrigin(name, o, b.state.Providers, s.cfg.Settings)
	e := alone.Origins[name]
	if len(alone.Problems) > 0 || e == nil {
		return &apiError{status: http.StatusUnprocessableEntity, msg: "the origin is invalid", problems: alone.Problems}
	}
	if why := needsRoot(e); why != "" && !b.holds(c, state.PermWrite, "/") {
		return forbidden("origin %s %s, which takes write on /", name, why)
	}
	for other, x := range b.origins {
		if other == name || b.readsOrigin(c, other) {
			continue
		}
		if state.Overlap(e.Prefix, x.Prefix) {
			return errorf(http.StatusConflict, "prefix %s overlaps prefix %s of origin %s, which you may not read", e.Prefix, x.Prefix, other)
		}
		if state.CommonNamesMayClash(e, x) {
			return errorf(http.StatusConflict, "its X.509 common names could equal those of origin %s, which you may not read", other)
		}
		if e.JWT != nil && x.JWT != nil && e.JWT.Issuer == x.JWT.Issuer && e.JWT.Audience == x.JWT.Audience {
			return errorf(http.StatusConflict, "origin %s, which you may not read, already takes tokens from %s with audience %s", other, x.JWT.Issuer, x.JWT.Audience)
		}
	}
	return nil
}

// needsRoot says why only those who may write / can create or change an
// origin, or returns "" when nothing does (SPEC sections 5.2 and 5.4).
func needsRoot(e *state.Expanded) string {
	switch {
	case e.Kind == state.KindExec:
		return "is an exec origin"
	case e.JWT != nil && !e.JWT.OriginAudience:
		return "takes tokens for an audience other than its origin audience"
	}
	return ""
}

func (s *Server) deleteOrigin(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name := r.PathValue("name")
	ch := &change{action: "delete", object: "origins/" + name, own: "origins." + name}
	ch.apply = func(b *base, next *state.State) error {
		if !b.readsOrigin(c, name) {
			return notFound("origin", name)
		}
		if prefix := b.origins[name].Prefix; !b.holds(c, state.PermWrite, prefix) {
			return forbidden("removing origin %s takes write on its prefix %s", name, prefix)
		}
		delete(next.Origins, name)
		return nil
	}
	s.write(w, r, c, ch)
}

func (s *Server) putMember(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name, member := r.PathValue("name"), r.PathValue("member")
	var m state.Member
	if err := readBody(w, r, &m); err != nil {
		writeError(w, err)
		return
	}
	ch := &change{action: "put", object: "origins/" + name + "/members/" + member, own: "origins." + name, answer: &m}
	ch.apply = func(b *base, next *state.State) error {
		if err := writableMembers(b, c, name); err != nil {
			return err
		}
		mine := next.Origins[name]
		ch.created = mine.Members[member] == nil
		if mine.Members == nil {
			mine.Members = map[string]*state.Member{}
		}
		mine.Members[member] = &m
		return nil
	}
	s.write(w, r, c, ch)
}

func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request, c caller, _ *base) {
	name, member := r.PathValue("name"), r.PathValue("member")
	ch := &change{action: "delete", object: "origins/" + name + "/members/" + member, own: "origins." + name}
	ch.apply = func(b *base, next *state.State) error {
		if !b.readsOrigin(c, name) || next.Origins[name].Members[member] == nil {
			return notFound("member", name+"/"+member)
		}
		if err := writableMembers(b, c, name); err != nil {
			return err
		}
		delete(next.Origins[name].Members, member)
		return nil
	}
	s.write(w, r, c, ch)
}

// writableMembers checks that the caller may change the members of the
// origin: it may read it, write on its prefix, and it is a keys origin.
func writableMembers(b *base, c caller, name string) error {
	if !b.readsOrigin(c, name) {
		return notFound("origin", name)
	}
	e := b.origins[name]
	if !b.holds(c, state.PermWrite, e.Prefix) {
		return forbidden("changing the members of origin %s takes write on its prefix %s", name, e.Prefix)
	}
	if e.Kind != state.KindKeys {
		return &apiError{status: http.StatusUnprocessableEntity, msg: "the change would make the state invalid", problems: state.Problems{{
			Path:    "origins." + name,
			Message: "only keys origins have members, and this is a " + string(e.Kind) + " origin",
		}}}
	}
	return nil
}
