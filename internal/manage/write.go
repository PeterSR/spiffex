package manage

import (
	"errors"
	"net/http"

	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// change is one write: what it does to the state, and how to answer.
type change struct {
	// action and object describe it for the log, such as "put" and
	// "origins/web".
	action, object string
	// own is the object written, as section.name, whose problems the
	// caller may see in full.
	own string
	// apply authorizes the change against b and returns the state it
	// makes, from a copy of b's. It returns an *apiError to refuse.
	apply func(b *base, next *state.State) error
	// answer is the body of a successful answer; nil means 204 No Content.
	answer any
	// created is set by apply when the write creates the object.
	created bool
}

// write makes a change with read, modify and compare-and-swap, against the
// state as stored, read afresh under the write lock. Without If-Match, a
// write that loses a race with another starts over against the newer
// state, authorized again; with If-Match, it fails with 412 instead. The
// token's ID is recorded only once the change is authorized and valid, just
// before it is stored, so callers without permission cannot fill the
// record. The state written is put in service in this process once it is
// stored.
func (s *Server) write(w http.ResponseWriter, r *http.Request, c caller, ch *change) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx := r.Context()
	conditional := len(r.Header.Values("If-Match")) > 0
	recorded := false
	for attempt := 1; ; attempt++ {
		b, err := s.load(ctx)
		if err != nil {
			writeError(w, err)
			return
		}
		if !s.issuable(b, c) {
			writeError(w, errUnauthenticated)
			return
		}
		if conditional && !ifMatch(r, b.version) {
			writeError(w, errorf(http.StatusPreconditionFailed, "the state is not at the version If-Match names"))
			return
		}
		next, err := clone(b.state)
		if err != nil {
			writeError(w, err)
			return
		}
		ch.created = false
		if err := ch.apply(b, next); err != nil {
			writeError(w, err)
			return
		}
		report := state.Validate(next, s.cfg.Settings)
		if len(report.Problems) > 0 {
			writeError(w, &apiError{
				status:   http.StatusUnprocessableEntity,
				msg:      "the change would make the state invalid",
				problems: b.visibleProblems(c, ch.own, report.Problems),
			})
			return
		}
		if !recorded {
			if !s.replay.use(c.tokenID, c.expires, s.cfg.Now()) {
				s.cfg.Logger.Warn("refused a management token used for a write before", "caller", c.id)
				writeError(w, errUnauthenticated)
				return
			}
			recorded = true
		}
		version, err := s.cfg.Store.Write(ctx, next, b.version)
		if errors.Is(err, store.ErrConflict) {
			if conditional {
				writeError(w, errorf(http.StatusPreconditionFailed, "the state changed while the write was made"))
				return
			}
			if attempt < maxWriteAttempts {
				continue
			}
			writeError(w, errorf(http.StatusServiceUnavailable, "the state kept changing while the write was made; try again"))
			return
		}
		if err != nil {
			s.cfg.Logger.Error("storing the state failed", "state", s.cfg.Store.String(), "error", err)
			writeError(w, errorf(http.StatusInternalServerError, "storing the state failed"))
			return
		}
		s.loaded = &base{version: version, state: next, origins: report.Origins, grants: report.Grants, overrides: report.Overrides}
		applied, err := s.cfg.Policy.Advance(b.version, &store.Snapshot{Version: version, State: next})
		switch {
		case err != nil:
			s.cfg.Logger.Error("the state stored through the management API could not be put in service", "version", version, "error", err)
		case !applied:
			s.cfg.Logger.Debug("the state in service is not the one the write built on; the next reload takes the write up", "version", version)
		}
		s.cfg.Logger.Info("state changed through the management API",
			"caller", c.id.String(), "action", ch.action, "object", ch.object, "version", version)
		switch {
		case ch.answer == nil:
			w.Header().Set("ETag", etag(version))
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		case ch.created:
			writeJSON(w, http.StatusCreated, version, ch.answer)
		default:
			writeJSON(w, http.StatusOK, version, ch.answer)
		}
		return
	}
}
