package keyset

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	if got := set.activeKey(c.t, delay); got.ID != current.ID {
		t.Fatalf("a backdated key signs as soon as it appears")
	}
	if got := set.activeKey(c.t.Add(delay), delay); got.ID != backdated.ID {
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
	if got := set.activeKey(c.t, delay); got.ID != signing.ID {
		t.Errorf("running watcher: signs with %s after the rewrite, want the previous signing key", got.File)
	}
	// A process started right after the rewrite sees only fresh mtimes.
	restarted, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.activeKey(c.t, delay); got.ID != signing.ID {
		t.Errorf("restarted process: signs with %s after the rewrite, want the previous signing key", got.File)
	}
	c.t = c.t.Add(delay)
	if got := set.activeKey(c.t, delay); got.ID != added.ID {
		t.Errorf("after the activation delay: signs with %s, want the added key", got.File)
	}
}

// A new key that fails the check is left out, and logged; a key already in
// service that starts failing is logged but kept, as dropping it would break
// the tokens it signed.
func TestWatcherChecksNewKeys(t *testing.T) {
	dir := t.TempDir()
	first, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	w, err := newWatcher(dir, slog.New(slog.NewTextHandler(&logs, nil)), func() time.Time { return t0.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]bool{}
	w.CheckNewKeys(func(path string) error {
		if bad[filepath.Base(path)] {
			return errors.New("readable by the verifier user")
		}
		return nil
	})
	second, err := Add(dir, ES256, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	bad[second.File] = true
	if w.Reload() {
		t.Error("a key failing its check changed the published keys")
	}
	if set, _, _ := w.Current(); len(set.Keys()) != 1 || set.Keys()[0].ID != first.ID {
		t.Errorf("keys in service: %v, want only the first", set.IDs())
	}
	if !strings.Contains(logs.String(), "not using a new signing key") {
		t.Errorf("the refused key was not logged:\n%s", logs.String())
	}

	bad[second.File] = false
	if !w.Reload() {
		t.Error("the key, once it passes, was not taken up")
	}
	bad[first.File] = true
	logs.Reset()
	w.Reload()
	if set, _, _ := w.Current(); len(set.Keys()) != 2 {
		t.Errorf("a key in service was dropped: %v", set.IDs())
	}
	if !strings.Contains(logs.String(), "a signing key in service fails its check") {
		t.Errorf("the key in service failing was not logged:\n%s", logs.String())
	}
	set, _, _ := w.Current()
	for _, k := range set.Keys() {
		if k.Exposed != (k.ID == first.ID) {
			t.Errorf("key %s: exposed %v", k.File, k.Exposed)
		}
	}
	if k, ok := set.Active(t0.Add(time.Hour), 0); !ok || k.ID != second.ID {
		t.Errorf("Active chose %s, %v; want the key that is not exposed", k.File, ok)
	}
	// Exposure sticks while the key stays, whatever later checks say.
	bad[first.File] = false
	w.Reload()
	if set, _, _ := w.Current(); !set.Keys()[0].Exposed {
		t.Error("an exposed key was trusted again after a passing check")
	}

	// With every key exposed, nothing may sign.
	bad[second.File] = true
	w.Reload()
	if set, _, _ := w.Current(); len(set.Keys()) != 2 {
		t.Errorf("exposed keys were unpublished: %v", set.IDs())
	} else if _, ok := set.Active(t0.Add(time.Hour), 0); ok {
		t.Error("Active chose a key with every key exposed")
	}

	// A key removed and added back is checked like a new one.
	path := filepath.Join(dir, first.File)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bad[first.File] = true
	w.Reload()
	if set, _, _ := w.Current(); slices.Contains(set.IDs(), first.ID) {
		t.Error("a key added back that fails its check was taken up")
	}
	bad[first.File] = false
	w.Reload()
	set, _, _ = w.Current()
	for _, k := range set.Keys() {
		if k.ID == first.ID && k.Exposed {
			t.Error("a key added back and passing its check is still marked exposed")
		}
	}
	if !slices.Contains(set.IDs(), first.ID) {
		t.Error("a key added back that passes its check was not taken up")
	}
}
