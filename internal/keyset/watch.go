package keyset

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Watcher keeps a Set loaded from a directory current. It polls rather than
// relying on file system events, because the usual delivery mechanisms
// (Kubernetes Secret volumes swap a symlink, network file systems emit
// nothing) make events unreliable.
//
// A key that appears in the directory while the watcher runs counts as
// published when the watcher first sees it, whatever its file name or
// modification time says. That keeps a key generated elsewhere, or restored
// from a backup, from signing before verifiers had a chance to learn it. A key
// the watcher already knows keeps its publication time when its file is
// rewritten.
type Watcher struct {
	dir    string
	logger *slog.Logger
	now    func() time.Time

	mu        sync.RWMutex
	check     func(path string) error
	set       *Set
	sequence  uint64
	changed   chan struct{}
	firstSeen map[string]time.Time
	// exposed holds the keys in service that once failed the check. They
	// stay exposed while they stay in the directory, whatever later checks
	// say: someone may have read them meanwhile.
	exposed map[string]bool
}

// NewWatcher loads dir once and fails if that fails: an issuer must not start
// without keys. A nil logger means slog.Default.
func NewWatcher(dir string, logger *slog.Logger) (*Watcher, error) {
	return newWatcher(dir, logger, time.Now)
}

func newWatcher(dir string, logger *slog.Logger, now func() time.Time) (*Watcher, error) {
	if logger == nil {
		logger = slog.Default()
	}
	set, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	firstSeen := make(map[string]time.Time, len(set.keys))
	var newest time.Time
	for _, k := range set.keys {
		firstSeen[k.ID] = k.Published
		if k.Published.After(newest) {
			newest = k.Published
		}
	}
	return &Watcher{
		dir:       dir,
		logger:    logger,
		now:       now,
		set:       set,
		sequence:  uint64(max(newest.Unix(), 1)),
		changed:   make(chan struct{}),
		firstSeen: firstSeen,
		exposed:   map[string]bool{},
	}, nil
}

// Current returns the current set, its sequence number, and a channel that is
// closed when the set is next replaced. The three are read together, so a
// change cannot slip in between reading the set and waiting on the channel.
//
// The sequence number increases every time the published keys change. Each
// watcher starts it at the newest key's publication time, so processes that
// load the same directory usually agree on it.
func (w *Watcher) Current() (*Set, uint64, <-chan struct{}) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.set, w.sequence, w.changed
}

// CheckNewKeys makes every reload check each key file with check. A new key
// that fails is left out, with an error logged: it is neither published nor
// signed with. A key already in service that fails is marked exposed: it
// stays published, since dropping it would break the tokens it signed, but
// never signs again while it stays in the directory. A key removed and added
// back counts as new. The issuer uses it to refuse keys an exec verifier
// could read.
func (w *Watcher) CheckNewKeys(check func(path string) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check = check
}

// Run polls the directory until ctx is done. A directory that fails to load
// keeps the previous set in service: losing all keys because of a half-written
// file would take the issuer down.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("poll interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.Reload()
		}
	}
}

// Reload loads the directory now and reports whether the published keys
// changed.
func (w *Watcher) Reload() bool {
	loaded, err := LoadDir(w.dir)
	if err != nil {
		w.logger.Error("reloading signing keys failed, keeping the previous set", "dir", w.dir, "error", err)
		return false
	}
	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	var keys []Key
	for _, k := range loaded.Keys() {
		_, known := w.firstSeen[k.ID]
		if w.check != nil {
			if err := w.check(filepath.Join(w.dir, k.File)); err != nil {
				if !known {
					w.logger.Error("not using a new signing key", "file", k.File, "error", err)
					continue
				}
				if !w.exposed[k.ID] {
					w.logger.Error("a signing key in service fails its check: it no longer signs, and should be replaced", "file", k.File, "error", err)
				}
				w.exposed[k.ID] = true
			}
		}
		k.Exposed = w.exposed[k.ID]
		keys = append(keys, k)
	}
	present := make(map[string]bool, len(keys))
	for i, k := range keys {
		present[k.ID] = true
		if seen, known := w.firstSeen[k.ID]; known {
			// Rewriting a file this process already publishes (a Secret
			// update rewrites them all) does not make it new again.
			keys[i].Published = seen
			continue
		}
		keys[i].Published = maxTime(k.Published, now)
		w.firstSeen[k.ID] = keys[i].Published
	}
	for id := range w.firstSeen {
		if !present[id] {
			delete(w.firstSeen, id)
			delete(w.exposed, id)
		}
	}
	set, err := NewSet(keys)
	if err != nil {
		w.logger.Error("reloading signing keys failed, keeping the previous set", "dir", w.dir, "error", err)
		return false
	}

	publishedChanged := !slices.Equal(set.IDs(), w.set.IDs())
	w.set = set
	if publishedChanged {
		w.sequence = max(w.sequence+1, uint64(now.Unix()))
		close(w.changed)
		w.changed = make(chan struct{})
		w.logger.Info("signing keys changed", "keys", len(keys), "sequence", w.sequence)
	}
	return publishedChanged
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
