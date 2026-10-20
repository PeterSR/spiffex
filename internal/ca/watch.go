package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Watcher keeps a Set loaded from the CA directory and the roots file
// current. It polls, like the key set's watcher, because the usual delivery
// mechanisms (Kubernetes Secret volumes swap a symlink, network file systems
// emit nothing) make events unreliable.
//
// What appears while the watcher runs counts as published when the watcher
// first sees it, whatever its file name or modification time says, and a
// certificate the watcher already knows keeps its publication time when its
// file is rewritten, exactly as for the signing keys. A certificate that
// fails its checks when it appears is logged and not used; one already in
// service that fails them later stays as it was.
type Watcher struct {
	opts   Options
	logger *slog.Logger
	now    func() time.Time

	mu        sync.RWMutex
	check     func(path string) error
	set       *Set
	sequence  uint64
	changed   chan struct{}
	firstSeen map[string]time.Time
	// revivedAt holds when an anchor that had left the bundle was published
	// again, for the anchors still in the directory.
	revivedAt map[string]time.Time
	// exposed holds the CAs in service whose key once failed the check.
	// They stay exposed while they stay in the directory.
	exposed map[string]bool
	byStem  map[string]CA
	// logged holds the last problem logged for each item, so that a file
	// that stays broken is logged once and not at every check.
	logged      map[string]string
	keyProblems map[string]string
	lastWarn    map[string]time.Time
}

// NewWatcher loads the CA once and fails if that fails: an issuer must not
// start with a CA it would refuse. A nil logger means slog.Default.
func NewWatcher(opts Options, logger *slog.Logger) (*Watcher, error) {
	return newWatcher(opts, logger, time.Now)
}

func newWatcher(opts Options, logger *slog.Logger, now func() time.Time) (*Watcher, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Warn == nil {
		opts.Warn = func(message string) {
			if strings.HasPrefix(message, NoKeyWarning) {
				logger.Error(message)
				return
			}
			logger.Warn(message)
		}
	}
	set, err := Load(opts, now())
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		opts:      opts,
		logger:    logger,
		now:       now,
		set:       set,
		changed:   make(chan struct{}),
		firstSeen: map[string]time.Time{},
		revivedAt: map[string]time.Time{},
		exposed:   map[string]bool{},
		byStem:    map[string]CA{},
		logged:    map[string]string{},
		lastWarn:  map[string]time.Time{},
	}
	var newest time.Time
	for _, a := range set.AllAnchors() {
		w.firstSeen[a.ID] = a.Published
		if a.Published.After(newest) {
			newest = a.Published
		}
	}
	for _, c := range set.CAs() {
		w.firstSeen[c.ID] = c.Published
		w.byStem[stemOf(c.File)] = c
	}
	w.sequence = uint64(max(newest.Unix(), 1))
	return w, nil
}

func stemOf(file string) string {
	return strings.TrimSuffix(strings.TrimPrefix(file, "ca-"), ".crt")
}

// Current returns the current set, its sequence number, and a channel that is
// closed when the published anchors next change. The three are read together,
// so a change cannot slip in between reading the set and waiting on the
// channel.
//
// The sequence number increases every time the published anchors change.
// Each watcher starts it at the newest anchor's publication time, so
// processes that load the same files usually agree on it.
func (w *Watcher) Current() (*Set, uint64, <-chan struct{}) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.set, w.sequence, w.changed
}

// CheckNewKeys makes every reload check each key file with check, as the key
// set's watcher does: a new CA whose key fails is left out with an error
// logged, and one in service is marked exposed, so that it stays published
// but never signs again.
func (w *Watcher) CheckNewKeys(check func(path string) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check = check
}

// Run polls until ctx is done.
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

// Reload reads the files now and reports whether the published anchors
// changed.
func (w *Watcher) Reload() bool {
	incumbents := map[string]*x509.Certificate{}
	for _, c := range w.set.CAs() {
		incumbents[c.ID] = c.Cert
	}
	r, err := readWith(w.opts, incumbents)
	if err != nil {
		w.logger.Error("reloading the CA failed, keeping the previous one", "dir", w.opts.Dir, "error", err)
		return false
	}
	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	failed := map[string]bool{}
	keyGone := map[string]bool{}
	problems := map[string]string{}
	for _, e := range r.errs {
		failed[e.key] = true
		keyGone[e.key] = keyGone[e.key] || e.keyGone
		if problems[e.key] != "" {
			problems[e.key] += "; "
		}
		problems[e.key] += e.err.Error()
	}
	cas, anchors := r.cas, r.anchors
	leftOut := map[string]bool{}
	for key, msg := range problems {
		if w.logged[key] == msg {
			continue
		}
		w.logged[key] = msg
		if _, inService := w.byStem[key]; inService && keyGone[key] {
			w.logger.Error("the key of a CA in service was removed: it no longer signs", "problem", msg)
		} else if inService {
			w.logger.Error("a CA certificate in service fails its checks: keeping the one in service", "problem", msg)
		} else {
			w.logger.Error("not using a CA certificate", "problem", msg)
		}
	}
	for key := range w.logged {
		if !failed[key] {
			delete(w.logged, key)
		}
	}
	// A generation whose files turn bad stays as it was, but one whose key
	// was removed is gone: removing the key is how a compromised CA is
	// stopped (SPEC section 2.4).
	var carried []CA
	for stem, prev := range w.byStem {
		if failed[stem] && !keyGone[stem] {
			carried = append(carried, prev)
		}
	}
	cas = append(slices.Clone(cas), carried...)
	if r.rootsFailed {
		for _, a := range w.set.AllAnchors() {
			if a.Source == RootsSource && !slices.ContainsFunc(anchors, func(have Anchor) bool { return have.ID == a.ID }) {
				anchors = append(anchors, a)
			}
		}
	}

	var kept []CA
	keyProblems := map[string]string{}
	for _, c := range cas {
		_, known := w.firstSeen[c.ID]
		if w.check != nil && c.Signer != nil {
			if err := w.check(filepath.Join(w.opts.Dir, c.KeyFile)); err != nil {
				if !known {
					keyProblems[c.KeyFile] = err.Error()
					if w.keyProblems[c.KeyFile] != err.Error() {
						w.logger.Error("not using a new CA key", "file", c.KeyFile, "error", err)
					}
					leftOut[c.ID] = true
					continue
				}
				if !w.exposed[c.ID] {
					w.logger.Error("a CA key in service fails its check: it no longer signs, and should be replaced", "file", c.KeyFile, "error", err)
				}
				w.exposed[c.ID] = true
			}
		}
		c.Exposed = w.exposed[c.ID]
		kept = append(kept, c)
	}
	w.keyProblems = keyProblems
	anchors = slices.DeleteFunc(anchors, func(a Anchor) bool {
		return leftOut[a.ID] && a.Source != RootsSource
	})
	// A CA kept for a file that now fails brings its anchor along, even when
	// the roots no longer list it. One read fresh has its anchor already, or
	// it would not have passed.
	byID := map[string]bool{}
	for _, a := range anchors {
		byID[a.ID] = true
	}
	for _, c := range carried {
		if id := certID(c.Anchor); !byID[id] {
			byID[id] = true
			anchors = append(anchors, Anchor{ID: id, Cert: c.Anchor, Published: c.Published, Source: c.File})
		}
	}

	present := map[string]bool{}
	for i, a := range anchors {
		present[a.ID] = true
		anchors[i].Published = w.published(a.ID, a.Published, now)
	}
	for i, c := range kept {
		present[c.ID] = true
		kept[i].Published = w.published(c.ID, c.Published, now)
	}
	for id := range w.firstSeen {
		if !present[id] {
			delete(w.firstSeen, id)
			delete(w.revivedAt, id)
			delete(w.exposed, id)
		}
	}
	set, err := newSet(kept, anchors, w.opts.ActivationDelay, w.opts.Retention, now, w.revivedAt)
	if err != nil {
		w.logger.Error("reloading the CA failed, keeping the previous one", "dir", w.opts.Dir, "error", err)
		return false
	}
	// An anchor that left the bundle and comes back, because a CA that chains
	// to it appeared, is new to verifiers that dropped it: it is published
	// again from now.
	revived := map[string]bool{}
	for _, a := range set.AllAnchors() {
		if w.set.AnchorRetired(a) && !set.AnchorRetired(a) {
			revived[a.ID] = true
			w.firstSeen[a.ID] = now
			w.revivedAt[a.ID] = now
		}
	}
	if len(revived) > 0 {
		for i, a := range anchors {
			if revived[a.ID] {
				anchors[i].Published = now
			}
		}
		for i, c := range kept {
			if revived[c.ID] {
				kept[i].Published = now
			}
		}
		if set, err = newSet(kept, anchors, w.opts.ActivationDelay, w.opts.Retention, now, w.revivedAt); err != nil {
			w.logger.Error("reloading the CA failed, keeping the previous one", "dir", w.opts.Dir, "error", err)
			return false
		}
	}
	if len(set.CAs()) == 0 && len(w.byStem) > 0 {
		w.logger.Error("no CA has a key any more: nothing signs X.509-SVIDs until one is added; the anchors stay published", "dir", w.opts.Dir)
	}
	w.byStem = map[string]CA{}
	for _, c := range set.CAs() {
		w.byStem[stemOf(c.File)] = c
	}

	publishedChanged := !slices.Equal(set.AnchorIDs(), w.set.AnchorIDs())
	w.set = set
	if publishedChanged {
		w.sequence = max(w.sequence+1, uint64(now.Unix()))
		close(w.changed)
		w.changed = make(chan struct{})
		w.logger.Info("CA anchors changed", "anchors", len(set.Anchors()), "sequence", w.sequence)
	}
	w.warnExpiry(set, now)
	return publishedChanged
}

// published returns when id counts as published: when this process first saw
// it, or the disk's word for it if it is new but older than the process.
func (w *Watcher) published(id string, disk, now time.Time) time.Time {
	if seen, known := w.firstSeen[id]; known {
		return seen
	}
	t := now
	if disk.After(t) {
		t = disk
	}
	w.firstSeen[id] = t
	return t
}

func (w *Watcher) warnExpiry(set *Set, now time.Time) {
	for _, c := range set.WarnExpiry(now) {
		if last, ok := w.lastWarn[c.ID]; ok && now.Sub(last) < time.Hour {
			continue
		}
		w.lastWarn[c.ID] = now
		w.logger.Warn("a CA that signs X.509-SVIDs expires soon: add its successor", "file", c.File, "not_after", c.NotAfter().Format(time.RFC3339))
	}
}
