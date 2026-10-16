// Package store keeps the issuer's state document (SPEC section 6.1) in one
// of three forms, each of which converts to the document without loss:
//
//   - a file: one YAML or JSON document, exactly as SPEC section 6.1 shows
//     it;
//   - a directory tree, described below;
//   - a Kubernetes ConfigMap holding the document under the key state.yaml,
//     read and written through the Kubernetes API with the issuer's own
//     service account.
//
// A state that does not exist yet is the empty state. Every form has a
// version: a hash of the content for files and trees, the resourceVersion
// for a ConfigMap. Writes are compare-and-swap: they name the version they
// replace and fail with ErrConflict when the stored state has changed since.
// Readers never see a half-written state. Writing goes through the document,
// so it rewrites a file or tree in a canonical form, without comments.
//
// # The directory tree
//
// The tree splits the document into one file per object, so each can be
// edited, reviewed and replaced on its own:
//
//	state/
//	  origins/
//	    kube.yaml                 the origin kube, as under origins in the document
//	    vms.yaml
//	    vms/members/billing.pub   member billing of origin vms: PEM PUBLIC KEY blocks
//	    vms/members/orders.jwk    member orders: a JWK, or a JWK Set for several keys
//	  providers/
//	    partner-idp.yaml          the provider partner-idp
//	  grants/
//	    operators.yaml            the grant operators
//
// Files may end in .yaml, .yml or .json. A member is given either in its
// origin's file, under members, or as a file under the origin's members
// directory, not both; a .pub file holds one PEM block per key. Two member
// files whose names differ only in case are an error, since they would be
// one file on some file systems; members named so, or with a leading dot,
// are written into their origin's file. Names that start with a dot are
// ignored, so editors' backup files do no harm; any other file the layout
// does not name is an error rather than silently left out.
//
// The issuer writes a tree by building a new one beside it and swapping a
// symbolic link, so the configured path becomes a link to the current tree.
// It then reads the tree back, and puts the previous one back unless it
// reads as exactly the document written.
package store

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
)

// Absent is the version of a state that does not exist yet. Writing with
// Absent creates the state, and fails if it exists.
const Absent = ""

// ErrConflict means the stored state is not the version a write replaces.
var ErrConflict = errors.New("the state has changed since it was read")

// Store holds the state document.
type Store interface {
	// Load reads the state. An error means it could not be read at all; a
	// state that was read but does not parse comes back as a Snapshot with
	// Problem set.
	Load(ctx context.Context) (*Snapshot, error)
	// Write replaces the state when its current version is ifVersion, and
	// returns the new version. The caller validates the state first.
	Write(ctx context.Context, st *state.State, ifVersion string) (string, error)
	// String says where the state is, for logs and messages.
	String() string
}

// Snapshot is the state as read, at one version.
type Snapshot struct {
	Version string
	// State is the parsed document. It is nil when Problem is set.
	State *state.State
	// Problem is why the stored state does not parse.
	Problem error
}

// Open returns the store for a location from the issuer's settings.
func Open(loc settings.StateLocation) (Store, error) {
	switch {
	case loc.File != "":
		return &File{Path: filepath.Clean(loc.File)}, nil
	case loc.Dir != "":
		return &Dir{Path: filepath.Clean(loc.Dir)}, nil
	case loc.ConfigMap != nil:
		return InCluster(loc.ConfigMap.Namespace, loc.ConfigMap.Name)
	}
	return nil, errors.New("no state location given")
}

// Watch loads the state every interval until ctx is done and calls apply
// with each new version. A file or tree can be caught halfway through being
// edited by hand, so for those a version is passed on only once two loads in
// a row have seen it. A ConfigMap changes as a whole and is passed on at
// once. Load errors are logged when they first occur, not on every attempt.
// since is the version already in service.
func Watch(ctx context.Context, s Store, since string, interval time.Duration, logger *slog.Logger, apply func(*Snapshot)) {
	w := watcher{store: s, logger: logger, applied: since, settle: settles(s), apply: apply}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

type watcher struct {
	store   Store
	logger  *slog.Logger
	settle  bool
	apply   func(*Snapshot)
	applied string
	seen    string
	hasSeen bool
	lastErr string
}

func (w *watcher) check(ctx context.Context) {
	snap, err := w.store.Load(ctx)
	if err != nil {
		w.hasSeen = false
		if msg := err.Error(); msg != w.lastErr {
			w.lastErr = msg
			w.logger.Error("the state cannot be read; keeping the state in service", "state", w.store.String(), "error", err)
		}
		return
	}
	if w.lastErr != "" {
		w.lastErr = ""
		w.logger.Info("the state can be read again", "state", w.store.String())
	}
	if snap.Version == w.applied {
		w.hasSeen = false
		return
	}
	if w.settle && (!w.hasSeen || snap.Version != w.seen) {
		w.seen, w.hasSeen = snap.Version, true
		return
	}
	w.hasSeen = false
	w.applied = snap.Version
	w.apply(snap)
}

func settles(s Store) bool {
	switch s.(type) {
	case *File, *Dir:
		return true
	}
	return false
}

func parsed(version string, data []byte) *Snapshot {
	st, err := state.ParseState(data)
	if err != nil {
		return &Snapshot{Version: version, Problem: err}
	}
	return &Snapshot{Version: version, State: st}
}

func empty(version string) *Snapshot {
	return &Snapshot{Version: version, State: &state.State{}}
}
