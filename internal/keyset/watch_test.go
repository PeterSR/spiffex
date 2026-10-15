package keyset

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestWatcherPicksUpNewKeys(t *testing.T) {
	dir := t.TempDir()
	first, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t0.Add(time.Hour)}
	w, err := newWatcher(dir, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	set, seq, changed := w.Current()
	if len(set.Keys()) != 1 || seq != uint64(t0.Unix()) {
		t.Fatalf("initial: %d keys, sequence %d", len(set.Keys()), seq)
	}

	if w.Reload() {
		t.Error("Reload reported a change with nothing changed")
	}
	select {
	case <-changed:
		t.Fatal("changed closed without a change")
	default:
	}

	second, err := Add(dir, ES256, c.t)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Reload() {
		t.Fatal("Reload missed a new key")
	}
	select {
	case <-changed:
	default:
		t.Fatal("changed not closed after a change")
	}
	set, seq2, _ := w.Current()
	if len(set.Keys()) != 2 || seq2 <= seq {
		t.Errorf("after adding: %d keys, sequence %d (was %d)", len(set.Keys()), seq2, seq)
	}

	// A second change within the same second still increases the sequence.
	if err := os.Remove(filepath.Join(dir, first.File)); err != nil {
		t.Fatal(err)
	}
	if !w.Reload() {
		t.Fatal("Reload missed a removed key")
	}
	set, seq3, _ := w.Current()
	if len(set.Keys()) != 1 || set.Keys()[0].ID != second.ID || seq3 <= seq2 {
		t.Errorf("after removing: keys %v, sequence %d (was %d)", set.IDs(), seq3, seq2)
	}
}

// A key whose file name claims it is old must still wait out the activation
// delay from the moment the watcher first saw it.
func TestWatcherDelaysBackdatedKeys(t *testing.T) {
	dir := t.TempDir()
	current, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t0.Add(48 * time.Hour)}
	w, err := newWatcher(dir, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	backdated, err := Add(dir, ES256, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	w.Reload()

	delay := time.Hour
	set, _, _ := w.Current()
	if got := set.Active(c.t, delay); got.ID != current.ID {
		t.Fatalf("a backdated key signs as soon as it appears")
	}
	if got := set.Active(c.t.Add(delay), delay); got.ID != backdated.ID {
		t.Errorf("backdated key not active after the activation delay")
	}
}

func TestWatcherKeepsSetOnLoadError(t *testing.T) {
	dir := t.TempDir()
	if _, err := Add(dir, ES256, t0); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	w, err := newWatcher(dir, slog.New(slog.NewTextHandler(&logs, nil)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName(t0.Add(time.Hour))), []byte("half-written"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w.Reload() {
		t.Error("Reload reported a change for a broken directory")
	}
	if set, _, _ := w.Current(); len(set.Keys()) != 1 {
		t.Errorf("set has %d keys, want the previous single key", len(set.Keys()))
	}
	if !strings.Contains(logs.String(), "keeping the previous set") {
		t.Errorf("load error not logged: %s", logs.String())
	}
}

// Renaming a key file changes its creation time but not what is published.
func TestWatcherRenameIsNotAPublishedChange(t *testing.T) {
	dir := t.TempDir()
	k, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := newWatcher(dir, quietLogger(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	renamed := FileName(t0.Add(time.Hour))
	if err := os.Rename(filepath.Join(dir, k.File), filepath.Join(dir, renamed)); err != nil {
		t.Fatal(err)
	}
	if w.Reload() {
		t.Error("a rename reported as a change of published keys")
	}
	if set, _, _ := w.Current(); set.Keys()[0].File != renamed {
		t.Errorf("watcher still serves the old file name %s", set.Keys()[0].File)
	}
}

func TestNewWatcherNilLogger(t *testing.T) {
	dir := t.TempDir()
	if _, err := Add(dir, ES256, t0); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName(t0.Add(time.Hour))), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.Reload()
}

// Rewriting every key file, as a Kubernetes Secret update does, must not
// change which key signs.
func TestSecretRewriteKeepsTheSigningKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := Add(dir, ES256, t0); err != nil {
		t.Fatal(err)
	}
	signing, err := Add(dir, ES256, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t0.Add(48 * time.Hour)}
	delay := time.Hour
	touchAll := func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Chtimes(filepath.Join(dir, e.Name()), c.t, c.t); err != nil {
				t.Fatal(err)
			}
		}
	}

	w, err := newWatcher(dir, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	added, err := Add(dir, ES256, c.t)
	if err != nil {
		t.Fatal(err)
	}
	touchAll()
	w.Reload()

	set, _, _ := w.Current()
	if got := set.Active(c.t, delay); got.ID != signing.ID {
		t.Errorf("running watcher: signs with %s after the rewrite, want the previous signing key", got.File)
	}
	// A process started right after the rewrite sees only fresh mtimes.
	restarted, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Active(c.t, delay); got.ID != signing.ID {
		t.Errorf("restarted process: signs with %s after the rewrite, want the previous signing key", got.File)
	}
	c.t = c.t.Add(delay)
	if got := set.Active(c.t, delay); got.ID != added.ID {
		t.Errorf("after the activation delay: signs with %s, want the added key", got.File)
	}
}
