package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/keyset"
)

// Removing the key of the only CA stops it, the compromise response of SPEC
// section 2.4. The anchors stay published and nothing signs until a CA is
// added. A restart behaves the same: it starts with no signing CA.
func TestRemovingTheOnlyCAKeyStopsSigning(t *testing.T) {
	for _, kind := range []string{"intermediate", "root"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			opts := testOptions(dir)
			var only CA
			if kind == "root" {
				only = initRoot(t, dir, t0)
			} else {
				roots := filepath.Join(t.TempDir(), "roots.pem")
				root, rootKey := operatorRoot(t, t0, true)
				writeRoots(t, roots, t0, root)
				opts.Roots = roots
				only = newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
			}
			c := &clock{t0.Add(5 * time.Hour)}
			logger, logs := capturedLogger()
			w, err := newWatcher(opts, logger, c.now)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, only.KeyFile)); err != nil {
				t.Fatal(err)
			}
			c.t = c.t.Add(time.Minute)
			w.Reload()
			set, _, _ := w.Current()
			if ch, err := set.Select(c.t, svidTTL); err == nil {
				t.Fatalf("the key file is gone, but %s still signs", ch.CA.File)
			}
			if len(set.CAs()) != 0 || len(set.Anchors()) != 1 {
				t.Errorf("%d CAs and %d anchors, want none and the anchor still published", len(set.CAs()), len(set.Anchors()))
			}
			if set.Usable(c.t, svidTTL) {
				t.Error("a set without a CA is usable, so discovery would announce X.509-SVIDs")
			}
			want := "key of a CA in service was removed"
			if kind == "root" {
				want = "no CA has a key any more"
			}
			if !strings.Contains(logs.String(), want) {
				t.Errorf("the log does not say %q:\n%s", want, logs.String())
			}
			// The restart behaves like the reload: no CA signs, the anchors stay.
			var warnings []string
			opts.Warn = func(m string) { warnings = append(warnings, m) }
			if restarted, err := Load(opts, c.t); err != nil || len(restarted.CAs()) != 0 || len(restarted.Anchors()) != 1 || restarted.Usable(c.t, svidTTL) {
				t.Errorf("startup after the key was removed: %v", err)
			}
			if len(warnings) == 0 {
				t.Error("startup without a CA key did not warn")
			}
			// A new CA brings signing back.
			if kind == "root" {
				initRoot(t, dir, c.t)
				w.Reload()
				if set, _, _ = w.Current(); len(set.CAs()) != 1 {
					t.Errorf("%d CAs after adding one", len(set.CAs()))
				}
			}
		})
	}
}

// The newest CA signs, to the end of its chain and then not at all. An older
// CA does not take over, because its anchor leaves the bundle once the newest
// has been active for the retention, and what it signed would outlive that.
func TestOlderCANeverSignsPastItsAnchor(t *testing.T) {
	dir := t.TempDir()
	older := initRoot(t, dir, t0)
	k := key(t)
	created := t0.Add(time.Hour)
	newer := issue(t, profileTemplate(t, k.Public(), "b", created, func(c *x509.Certificate) {
		c.NotAfter = t0.Add(3*time.Hour + 40*time.Minute)
	}), k.Public(), nil, k)
	install(t, dir, created, k, newer)

	at := t0.Add(3 * time.Hour)
	set, err := Load(testOptions(dir), at)
	if err != nil {
		t.Fatal(err)
	}
	choice, err := set.Select(at, svidTTL)
	if err != nil {
		t.Fatal(err)
	}
	if choice.CA.File == older.File || !choice.Shortened || !choice.NotAfter.Equal(t0.Add(3*time.Hour+40*time.Minute)) {
		t.Fatalf("selected %s until %s (shortened %v): want the newer CA, clamped to its chain", choice.CA.File, choice.NotAfter, choice.Shortened)
	}
	for _, now := range []time.Time{t0.Add(3*time.Hour + 36*time.Minute), t0.Add(3*time.Hour + 41*time.Minute), t0.Add(3*time.Hour + 11*time.Minute)} {
		if ch, err := set.Select(now, svidTTL); err == nil && ch.CA.File == older.File {
			t.Errorf("the older CA signs at %s", now)
		}
	}
}

// The unique-subject rule also holds at import, before anything is written,
// so the issuer does not refuse to start with what was imported.
func TestImportRefusesASharedSubject(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	fixed := mustName(t, "example.org", "operator-chosen name")

	importAt := func(at time.Time) error {
		_, csr, err := NewCSR(dir, td, keyset.ES256, at)
		if err != nil {
			t.Fatal(err)
		}
		req := parseCSR(t, csr)
		cert := signIntermediate(t, req.PublicKey, "", at, root, rootKey, func(c *x509.Certificate) { c.RawSubject = fixed })
		_, err = Import(opts, certificatePEM(cert), at)
		return err
	}
	if err := importAt(t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	err := importAt(t0.Add(2 * time.Hour))
	if err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("second import: %v, want the shared subject refused", err)
	}
	if _, err := Load(opts, t0.Add(3*time.Hour)); err != nil {
		t.Errorf("the issuer would not start after the refused import: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, CertFileName(t0.Add(2*time.Hour)))); !os.IsNotExist(err) {
		t.Errorf("the refused certificate was written (%v)", err)
	}
}

// A newcomer with the subject of a CA in service is the one refused, whatever
// its time says.
func TestNewcomerDoesNotDisplaceTheCAInService(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	same := func(c *x509.Certificate) { c.RawSubject = mustName(t, "example.org", "one name") }
	incumbentKey := key(t)
	install(t, dir, t0.Add(time.Hour), incumbentKey, signIntermediate(t, incumbentKey.Public(), "", t0, root, rootKey, same))

	c := &clock{t0.Add(5 * time.Hour)}
	logger, logs := capturedLogger()
	w, err := newWatcher(opts, logger, c.now)
	if err != nil {
		t.Fatal(err)
	}
	newcomerKey := key(t)
	install(t, dir, t0, newcomerKey, signIntermediate(t, newcomerKey.Public(), "", t0, root, rootKey, same))
	w.Reload()
	set, _, _ := w.Current()
	if cas := set.CAs(); len(cas) != 1 || cas[0].File != CertFileName(t0.Add(time.Hour)) {
		t.Errorf("CAs in service: %d, want only the incumbent", len(cas))
	}
	if !strings.Contains(logs.String(), "not using a CA certificate") {
		t.Errorf("the refusal of the newcomer was not logged:\n%s", logs.String())
	}
}

// While ca_roots cannot be read, the roots from the last good read are kept,
// and a copy of one of them in ca_dir does not make the set invalid.
func TestUnreadableRootsDoNotDuplicateAnchors(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	install(t, dir, t0, nil, root)
	a := newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
	b := newIntermediate(t, opts, t0.Add(2*time.Hour), root, rootKey, nil)
	c := &clock{t0.Add(5 * time.Hour)}
	w, err := newWatcher(opts, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, b.KeyFile)); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	w.Reload()
	set, _, _ := w.Current()
	if got := signingFile(t, set, c.t); got != a.File {
		t.Errorf("signing with %s after the newer key was removed, want %s", got, a.File)
	}
	if len(set.Anchors()) != 1 {
		t.Errorf("%d anchors, want the one root once", len(set.Anchors()))
	}
}

// ca_roots_dedicated is the operator's word about ca_roots, not about
// certificates kept in ca_dir.
func TestKeylessCertificatesInCADirNeedTheFullConstraints(t *testing.T) {
	dir := t.TempDir()
	initRoot(t, dir, t0)
	loose, _ := operatorRoot(t, t0, false)
	install(t, dir, t0.Add(time.Hour), nil, loose)
	opts := testOptions(dir)
	opts.Roots = filepath.Join(t.TempDir(), "roots.pem")
	writeRoots(t, opts.Roots, t0, loose)
	opts.RootsDedicated = true
	_, err := Load(opts, t0.Add(3*time.Hour))
	if err == nil || !strings.Contains(err.Error(), CertFileName(t0.Add(time.Hour))) || !strings.Contains(err.Error(), "full name constraints") {
		t.Errorf("err = %v, want the unconstrained certificate in ca_dir refused although the roots are declared dedicated", err)
	}
	constrained, _ := operatorRoot(t, t0, true)
	if err := os.WriteFile(filepath.Join(dir, CertFileName(t0.Add(time.Hour))), certificatePEM(constrained), 0o644); err != nil {
		t.Fatal(err)
	}
	opts.Roots = ""
	opts.RootsDedicated = false
	if _, err := Load(opts, t0.Add(3*time.Hour)); err != nil {
		t.Errorf("a constrained keyless root in ca_dir: %v", err)
	}
}

// Known limits (DECISIONS, docs/configuration.md): the issuer keeps no state
// across a restart, so what it learns from file times is lost with it.
func TestKnownLimitsAcrossARestart(t *testing.T) {
	t.Run("a slow ceremony under an old root", func(t *testing.T) {
		dir := t.TempDir()
		rootsPath := filepath.Join(t.TempDir(), "roots.pem")
		r1, r1k := operatorRoot(t, t0, true)
		k1 := key(t)
		install(t, dir, t0, k1, signIntermediate(t, k1.Public(), "i1", t0, r1, r1k, nil))
		now := t0.Add(10 * 24 * time.Hour)
		r2, r2k := operatorRoot(t, t0.Add(-365*24*time.Hour), true)
		k2 := key(t)
		csrAt := now.Add(-3 * 24 * time.Hour)
		install(t, dir, csrAt, k2, signIntermediate(t, k2.Public(), "i2", now.Add(-2*24*time.Hour), r2, r2k, nil))
		touch(t, dir, now.Add(-time.Minute), CertFileName(csrAt))
		writeRoots(t, rootsPath, now.Add(-2*time.Minute), r1, r2)
		opts := testOptions(dir)
		opts.Roots = rootsPath
		set, err := Load(opts, now)
		if err != nil {
			t.Fatal(err)
		}
		// Nothing in the files says the root was listed two minutes ago and
		// not long since, so the new intermediate signs at once. The docs
		// tell the operator to wait for activation_delay before restarting.
		if got := signingFile(t, set, now); got != CertFileName(csrAt) {
			t.Errorf("signing with %s; the documented limit changed", got)
		}
	})

	t.Run("a retired root that returns while the issuer is down", func(t *testing.T) {
		dir := t.TempDir()
		roots := filepath.Join(t.TempDir(), "roots.pem")
		r1, k1 := operatorRoot(t, t0, true)
		writeRoots(t, roots, t0, r1)
		opts := testOptions(dir)
		opts.Roots = roots
		var warnings []string
		opts.Warn = func(m string) { warnings = append(warnings, m) }
		newIntermediate(t, opts, t0.Add(time.Hour), r1, k1, nil)
		r2, k2 := operatorRoot(t, t0.Add(10*time.Hour), true)
		writeRoots(t, roots, t0.Add(10*time.Hour), r1, r2)
		newIntermediate(t, opts, t0.Add(11*time.Hour), r2, k2, nil)
		if len(warnings) != 0 {
			t.Fatalf("warnings for ordinary imports: %v", warnings)
		}
		if set, err := Load(opts, t0.Add(20*time.Hour)); err != nil || len(set.Anchors()) != 1 {
			t.Fatalf("the first root should have left the bundle: %v", err)
		}
		third := newIntermediate(t, opts, t0.Add(30*time.Hour), r1, k1, nil)
		if len(warnings) != 1 || !strings.Contains(warnings[0], "left the bundle") {
			t.Errorf("warnings = %v, want one saying the root left the bundle", warnings)
		}
		now := t0.Add(30*time.Hour + time.Minute)
		set, err := Load(opts, now)
		if err != nil {
			t.Fatal(err)
		}
		if got := signingFile(t, set, now); got != third.File {
			t.Errorf("signing with %s; the documented limit changed", got)
		}
	})
}

// A self-signed newcomer with the subject of a CA in service is the one
// refused: its own anchor must not count against the incumbent.
func TestSelfSignedNewcomerDoesNotDisplaceTheCAInService(t *testing.T) {
	for _, kind := range []string{"root incumbent", "intermediate incumbent"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			opts := testOptions(dir)
			var incumbent CA
			if kind == "root incumbent" {
				incumbent = initRoot(t, dir, t0)
			} else {
				roots := filepath.Join(t.TempDir(), "roots.pem")
				root, rootKey := operatorRoot(t, t0, true)
				writeRoots(t, roots, t0, root)
				opts.Roots = roots
				incumbent = newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
			}
			c := &clock{t0.Add(5 * time.Hour)}
			logger, logs := capturedLogger()
			w, err := newWatcher(opts, logger, c.now)
			if err != nil {
				t.Fatal(err)
			}
			k := key(t)
			created := t0.Add(4 * time.Hour)
			newcomer := issue(t, profileTemplate(t, k.Public(), "x", created, func(x *x509.Certificate) {
				x.RawSubject = incumbent.Cert.RawSubject
			}), k.Public(), nil, k)
			install(t, dir, created, k, newcomer)
			c.t = c.t.Add(time.Minute)
			w.Reload()
			set, _, _ := w.Current()
			if cas := set.CAs(); len(cas) != 1 || cas[0].File != incumbent.File {
				t.Errorf("%d CAs in service, want only the incumbent; log:\n%s", len(cas), logs.String())
			}
			if len(set.Anchors()) != 1 {
				t.Errorf("%d anchors, want the incumbent's alone", len(set.Anchors()))
			}
		})
	}
}

// An anchor that comes back after leaving the bundle keeps its activation
// delay even when the CA under it is the only one left, which the fallback
// that trusts creation times would otherwise skip.
func TestRevivedAnchorWaitsEvenForTheOnlyCA(t *testing.T) {
	for _, kind := range []string{"intermediate", "root"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			opts := testOptions(dir)
			var older, newer CA
			if kind == "root" {
				older = initRoot(t, dir, t0)
				newer = initRoot(t, dir, t0.Add(10*time.Hour))
			} else {
				roots := filepath.Join(t.TempDir(), "roots.pem")
				r1, k1 := operatorRoot(t, t0, true)
				writeRoots(t, roots, t0, r1)
				opts.Roots = roots
				older = newIntermediate(t, opts, t0.Add(time.Hour), r1, k1, nil)
				r2, k2 := operatorRoot(t, t0.Add(10*time.Hour), true)
				writeRoots(t, roots, t0.Add(10*time.Hour), r1, r2)
				newer = newIntermediate(t, opts, t0.Add(11*time.Hour), r2, k2, nil)
			}
			c := &clock{t0.Add(20 * time.Hour)}
			w, err := newWatcher(opts, quietLogger(), c.now)
			if err != nil {
				t.Fatal(err)
			}
			if set, _, _ := w.Current(); len(set.Anchors()) != 1 {
				t.Fatalf("%d anchors, want the older root retired", len(set.Anchors()))
			}
			// The newer key is compromised and goes.
			if err := os.Remove(filepath.Join(dir, newer.KeyFile)); err != nil {
				t.Fatal(err)
			}
			c.t = c.t.Add(time.Minute)
			w.Reload()
			set, _, _ := w.Current()
			if len(set.Anchors()) != 2 {
				t.Fatalf("%d anchors, want the older root published again", len(set.Anchors()))
			}
			if ch, err := set.Select(c.t, svidTTL); err == nil {
				t.Errorf("%s signs at once under a root that was just republished", ch.CA.File)
			}
			c.t = c.t.Add(delay + time.Minute)
			w.Reload()
			set, _, _ = w.Current()
			if got := signingFile(t, set, c.t); got != older.File {
				t.Errorf("after the delay signing with %s, want %s", got, older.File)
			}
		})
	}
}

// The compromise response, removing a key and keeping the certificate, must
// leave an issuer that restarts: the keyless intermediate is skipped.
func TestRestartAfterKeyRemoval(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	var warnings []string
	opts.Warn = func(m string) { warnings = append(warnings, m) }
	first := newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
	second := newIntermediate(t, opts, t0.Add(2*time.Hour), root, rootKey, nil)
	if err := os.Remove(filepath.Join(dir, second.KeyFile)); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(5 * time.Hour)
	set, err := Load(opts, now)
	if err != nil {
		t.Fatalf("restart fails after removing the key of one of two CAs: %v", err)
	}
	if got := signingFile(t, set, now); got != first.File {
		t.Errorf("signing with %s, want %s", got, first.File)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], second.File) || strings.Contains(warnings[0], "list the root") || !strings.Contains(warnings[1], first.File+" signs now") {
		t.Errorf("warnings = %v, want one naming the keyless certificate and one that the older CA signs", warnings)
	}
}

// A start with anchors and no key is logged as an error and names the cause.
func TestStartWithoutAnyCAKeyLogsAnError(t *testing.T) {
	dir := t.TempDir()
	only := initRoot(t, dir, t0)
	if err := os.Remove(filepath.Join(dir, only.KeyFile)); err != nil {
		t.Fatal(err)
	}
	logger, logs := capturedLogger()
	if _, err := newWatcher(testOptions(dir), logger, (&clock{t0.Add(time.Hour)}).now); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "ERROR") || !strings.Contains(out, "key file is missing or was removed") {
		t.Errorf("log:\n%s", out)
	}
}
