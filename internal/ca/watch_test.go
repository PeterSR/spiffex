package ca

import (
	"bytes"
	"context"
	"crypto/x509"
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

func capturedLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func TestWatcherPicksUpNewRoots(t *testing.T) {
	dir := t.TempDir()
	first := initRoot(t, dir, t0)
	c := &clock{t0.Add(time.Hour)}
	w, err := newWatcher(testOptions(dir), quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	set, seq, changed := w.Current()
	if len(set.Anchors()) != 1 || seq != uint64(t0.Unix()) {
		t.Fatalf("initial: %d anchors, sequence %d", len(set.Anchors()), seq)
	}
	if w.Reload() {
		t.Error("Reload reported a change with nothing changed")
	}
	select {
	case <-changed:
		t.Fatal("changed closed without a change")
	default:
	}

	c.t = t0.Add(2 * time.Hour)
	second := initRoot(t, dir, c.t)
	if !w.Reload() {
		t.Fatal("Reload missed a new root")
	}
	select {
	case <-changed:
	default:
		t.Fatal("changed not closed after a change")
	}
	set, seq2, _ := w.Current()
	if len(set.Anchors()) != 2 || seq2 <= seq {
		t.Errorf("after adding: %d anchors, sequence %d (was %d)", len(set.Anchors()), seq2, seq)
	}
	if got := signingFile(t, set, c.t); got != first.File {
		t.Errorf("signing with %s the moment the new root appears, want %s", got, first.File)
	}
	c.t = c.t.Add(delay)
	w.Reload()
	if set, _, _ = w.Current(); signingFile(t, set, c.t) != second.File {
		t.Errorf("not signing with the new root after the delay")
	}

	// Removing the first root changes the anchors again, within the same
	// second too.
	for _, name := range []string{first.File, first.KeyFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if !w.Reload() {
		t.Fatal("Reload missed a removed root")
	}
	set, seq3, _ := w.Current()
	if len(set.Anchors()) != 1 || seq3 <= seq2 {
		t.Errorf("after removing: %d anchors, sequence %d (was %d)", len(set.Anchors()), seq3, seq2)
	}
}

// A new CA under an anchor already published changes what signs but not what
// is published, so the sequence stays.
func TestWatcherSequenceFollowsAnchors(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)

	c := &clock{t0.Add(2 * time.Hour)}
	w, err := newWatcher(opts, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	_, seq, _ := w.Current()
	c.t = t0.Add(3 * time.Hour)
	added := newIntermediate(t, opts, c.t, root, rootKey, nil)
	if w.Reload() {
		t.Error("a new intermediate under a published root reported a change in what is published")
	}
	set, seq2, _ := w.Current()
	if len(set.CAs()) != 2 || seq2 != seq {
		t.Errorf("%d CAs, sequence %d (was %d)", len(set.CAs()), seq2, seq)
	}
	if signingFile(t, set, c.t) != added.File {
		t.Error("the new intermediate does not sign at once")
	}

	root2, _ := operatorRoot(t, c.t, true)
	writeRoots(t, roots, c.t, root, root2)
	if !w.Reload() {
		t.Fatal("a new root in ca_roots was not noticed")
	}
	if _, seq3, _ := w.Current(); seq3 <= seq2 {
		t.Errorf("sequence %d did not grow past %d", seq3, seq2)
	}
}

// A new certificate that fails its checks is not used and not published, and
// one already in service that is later damaged stays as it was.
func TestWatcherKeepsWhatItHasOnBadFiles(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	inter := newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
	selfSigned := initRoot(t, dir, t0.Add(2*time.Hour))

	logger, logs := capturedLogger()
	c := &clock{t0.Add(5 * time.Hour)}
	w, err := newWatcher(opts, logger, c.now)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := w.Current()

	// A new generation with a certificate that does not meet the profile.
	k := key(t)
	bad := issue(t, profileTemplate(t, k.Public(), "no constraints", c.t, func(x *x509.Certificate) { x.ExtraExtensions = nil }), k.Public(), nil, k)
	install(t, dir, c.t, k, bad)
	// And one that is not a certificate at all.
	if err := os.WriteFile(filepath.Join(dir, CertFileName(c.t.Add(time.Minute))), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w.Reload() {
		t.Error("a bad certificate changed what is published")
	}
	set, _, _ := w.Current()
	if len(set.CAs()) != len(before.CAs()) || !slices.Equal(set.AnchorIDs(), before.AnchorIDs()) {
		t.Errorf("a bad certificate changed the CA: %d CAs", len(set.CAs()))
	}
	if !strings.Contains(logs.String(), "not using a CA certificate") {
		t.Errorf("nothing logged about a bad certificate:\n%s", logs.String())
	}
	logs.Reset()
	w.Reload()
	if logs.Len() != 0 {
		t.Errorf("the same problem was logged again:\n%s", logs.String())
	}

	// A certificate in service damaged on disk stays in service, with its
	// anchor, even when the roots file also goes.
	if err := os.WriteFile(filepath.Join(dir, inter.File), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	set, _, _ = w.Current()
	var files []string
	for _, ca := range set.CAs() {
		files = append(files, ca.File)
	}
	if !slices.Contains(files, inter.File) || !slices.Contains(files, selfSigned.File) {
		t.Errorf("CAs in service = %v, want %s and %s kept", files, inter.File, selfSigned.File)
	}
	if !slices.Equal(set.AnchorIDs(), before.AnchorIDs()) {
		t.Error("a damaged roots file changed the anchors")
	}
	if !strings.Contains(logs.String(), "keeping the one in service") {
		t.Errorf("nothing logged about a damaged certificate in service:\n%s", logs.String())
	}
}

func TestWatcherStartupRefusesBadFiles(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, _ := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	// An intermediate whose root is not among the roots.
	otherRoot, otherKey := operatorRoot(t, t0, true)
	k := key(t)
	inter := signIntermediate(t, k.Public(), "orphan", t0, otherRoot, otherKey, nil)
	install(t, dir, t0, k, inter)
	if _, err := NewWatcher(opts, quietLogger()); err == nil || !strings.Contains(err.Error(), "does not chain to an anchor") {
		t.Errorf("a chain that ends nowhere: %v", err)
	}
	// One good CA does not excuse a bad one.
	initRoot(t, dir, t0.Add(time.Hour))
	if _, err := NewWatcher(opts, quietLogger()); err == nil {
		t.Error("the issuer started with a CA that fails its chain")
	}
}

// A certificate named for the past still waits out the delay from the moment
// the watcher first saw it.
func TestWatcherDelaysBackdatedCAs(t *testing.T) {
	dir := t.TempDir()
	old := initRoot(t, dir, t0)
	c := &clock{t0.Add(50 * time.Hour)}
	w, err := newWatcher(testOptions(dir), quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	backdated := initRoot(t, dir, t0.Add(10*time.Hour))
	touch(t, dir, t0.Add(10*time.Hour), backdated.File)
	w.Reload()
	set, _, _ := w.Current()
	if len(set.Anchors()) != 2 {
		t.Fatalf("%d anchors, want the backdated root published", len(set.Anchors()))
	}
	if got := signingFile(t, set, c.t.Add(delay-time.Second)); got != old.File {
		t.Errorf("signing with %s before the delay from first sight, want %s", got, old.File)
	}
	if got := signingFile(t, set, c.t.Add(delay)); got != backdated.File {
		t.Errorf("signing with %s after the delay, want %s", got, backdated.File)
	}
	// Rewriting the files of a CA already known does not make it new again.
	touch(t, dir, c.t.Add(time.Minute), old.File, old.KeyFile, backdated.File, backdated.KeyFile)
	c.t = c.t.Add(delay)
	w.Reload()
	set, _, _ = w.Current()
	if got := signingFile(t, set, c.t); got != backdated.File {
		t.Errorf("signing with %s after a rewrite, want %s", got, backdated.File)
	}
}

func TestWatcherExposedKeys(t *testing.T) {
	dir := t.TempDir()
	first := initRoot(t, dir, t0)
	c := &clock{t0.Add(5 * time.Hour)}
	logger, logs := capturedLogger()
	w, err := newWatcher(testOptions(dir), logger, c.now)
	if err != nil {
		t.Fatal(err)
	}
	var readable []string
	w.CheckNewKeys(func(path string) error {
		if slices.Contains(readable, filepath.Base(path)) {
			return errors.New("the verifier user could read it")
		}
		return nil
	})

	// A new CA whose key could be read is neither used nor published.
	second := initRoot(t, dir, c.t)
	readable = append(readable, second.KeyFile)
	w.Reload()
	set, _, _ := w.Current()
	if len(set.CAs()) != 1 || len(set.Anchors()) != 1 {
		t.Fatalf("%d CAs and %d anchors, want the exposed new one left out", len(set.CAs()), len(set.Anchors()))
	}
	if !strings.Contains(logs.String(), "not using a new CA key") {
		t.Errorf("logs:\n%s", logs.String())
	}

	// The key was fixed, so it is let in, and later exposed in service: it
	// stays published, and no longer signs.
	readable = nil
	w.Reload()
	c.t = c.t.Add(delay)
	w.Reload()
	set, _, _ = w.Current()
	if len(set.CAs()) != 2 || signingFile(t, set, c.t) != second.File {
		t.Fatalf("%d CAs, signing %s", len(set.CAs()), signingFile(t, set, c.t))
	}
	readable = append(readable, second.KeyFile)
	w.Reload()
	set, _, _ = w.Current()
	if got := signingFile(t, set, c.t); got != first.File {
		t.Errorf("signing with %s with the newer key exposed, want %s", got, first.File)
	}
	if len(set.Anchors()) != 2 {
		t.Errorf("%d anchors: an exposed CA stays published", len(set.Anchors()))
	}
	// And so does it when everything is exposed: nothing signs.
	readable = append(readable, first.KeyFile)
	w.Reload()
	set, _, _ = w.Current()
	if _, err := set.Select(c.t, svidTTL); !errors.Is(err, ErrNoSigningCA) {
		t.Errorf("with every key exposed: %v", err)
	}
}

func TestWatcherRunStopsWithContext(t *testing.T) {
	dir := t.TempDir()
	initRoot(t, dir, t0)
	w, err := NewWatcher(testOptions(dir), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, time.Millisecond) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := w.Run(context.Background(), 0); err == nil {
		t.Error("a zero interval was accepted")
	}
}

func TestWatcherWarnsBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	k := key(t)
	cert := issue(t, profileTemplate(t, k.Public(), "soon", t0, func(c *x509.Certificate) { c.NotAfter = t0.Add(10 * 24 * time.Hour) }), k.Public(), nil, k)
	install(t, dir, t0, k, cert)
	logger, logs := capturedLogger()
	c := &clock{t0.Add(2 * time.Hour)}
	w, err := newWatcher(testOptions(dir), logger, c.now)
	if err != nil {
		t.Fatal(err)
	}
	w.Reload()
	if !strings.Contains(logs.String(), "expires soon") {
		t.Fatalf("no warning:\n%s", logs.String())
	}
	logs.Reset()
	w.Reload()
	if logs.Len() != 0 {
		t.Errorf("warned at every check:\n%s", logs.String())
	}
	c.t = c.t.Add(time.Hour + time.Minute)
	w.Reload()
	if !strings.Contains(logs.String(), "expires soon") {
		t.Error("no warning an hour later")
	}
}
