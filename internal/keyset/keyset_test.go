package keyset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestAddAndLoad(t *testing.T) {
	dir := t.TempDir()
	es, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Add(dir, RS256, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	keys := set.Keys()
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].ID != es.ID || keys[0].Algorithm != ES256 || !keys[0].Created.Equal(t0) {
		t.Errorf("first key = %+v, want the ES256 key created at %s", keys[0], t0)
	}
	if keys[1].ID != rs.ID || keys[1].Algorithm != RS256 {
		t.Errorf("second key = %+v, want the RS256 key", keys[1])
	}
	info, err := os.Stat(filepath.Join(dir, es.File))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 600", mode)
	}
}

func TestAddRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, err := Add(dir, ES256, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(dir, ES256, t0); err == nil {
		t.Fatal("second Add at the same second succeeded, want an error")
	}
}

func TestLoadDirErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := LoadDir(t.TempDir()); err == nil {
			t.Fatal("want an error for a directory without keys")
		}
	})
	t.Run("unparseable key", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, FileName(t0)), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDir(dir); err == nil {
			t.Fatal("want an error for a key file that does not parse")
		}
	})
	t.Run("small RSA key", func(t *testing.T) {
		dir := t.TempDir()
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		data, err := MarshalPrivateKey(weak)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, FileName(t0)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = LoadDir(dir)
		if err == nil || !strings.Contains(err.Error(), "too small") {
			t.Fatalf("err = %v, want a too-small error", err)
		}
	})
	t.Run("duplicate key", func(t *testing.T) {
		dir := t.TempDir()
		k, err := Add(dir, ES256, t0)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, k.File))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, FileName(t0.Add(time.Hour))), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDir(dir); err == nil {
			t.Fatal("want an error for the same key in two files")
		}
	})
}

func TestActive(t *testing.T) {
	keys := []Key{
		testKey(t, t0),
		testKey(t, t0.Add(10*time.Hour)),
		testKey(t, t0.Add(20*time.Hour)),
	}
	set, err := NewSet([]Key{keys[2], keys[0], keys[1]})
	if err != nil {
		t.Fatal(err)
	}
	delay := time.Hour
	cases := []struct {
		name string
		now  time.Time
		want Key
	}{
		{"before any key is old enough falls back to the oldest", t0.Add(30 * time.Minute), keys[0]},
		{"first key activated", t0.Add(time.Hour), keys[0]},
		{"second key published but not active", t0.Add(10*time.Hour + 59*time.Minute), keys[0]},
		{"second key active", t0.Add(11 * time.Hour), keys[1]},
		{"newest key active", t0.Add(21 * time.Hour), keys[2]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := set.Active(c.now, delay); got.ID != c.want.ID {
				t.Errorf("Active = %s, want %s", got.Created, c.want.Created)
			}
		})
	}
}

func TestRetiredAndPrune(t *testing.T) {
	dir := t.TempDir()
	old, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(dir, ES256, t0.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	delay, ttl := time.Hour, 5*time.Minute
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// The old key stops signing at 11:00 after t0 and may be needed for one
	// more token lifetime.
	if got := set.Retired(t0.Add(11*time.Hour+4*time.Minute), delay, ttl); len(got) != 0 {
		t.Errorf("retired %d keys while tokens signed by the old key may be live", len(got))
	}
	removed, err := Prune(dir, t0.Add(11*time.Hour+5*time.Minute), delay, ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].ID != old.ID {
		t.Fatalf("Prune removed %v, want the old key", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, old.File)); !os.IsNotExist(err) {
		t.Errorf("old key file still exists: %v", err)
	}
	set, err = LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys()) != 1 {
		t.Errorf("%d keys left, want 1", len(set.Keys()))
	}
}

func TestIDsIgnoreOrder(t *testing.T) {
	a, b := testKey(t, t0), testKey(t, t0.Add(time.Hour))
	s1, err := NewSet([]Key{a, b})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSet([]Key{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s1.IDs(), s2.IDs()) {
		t.Error("IDs differ for the same keys")
	}
}

func TestParsePrivateKeyFormats(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384PKCS8, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	block := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }

	good := map[string][]byte{
		"SEC 1":  block("EC PRIVATE KEY", sec1),
		"PKCS#1": block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)),
	}
	for name, data := range good {
		if _, err := ParsePrivateKey(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string][]byte{
		"P-384":        block("PRIVATE KEY", p384PKCS8),
		"Ed25519":      block("PRIVATE KEY", edPKCS8),
		"certificate":  block("CERTIFICATE", []byte{1, 2, 3}),
		"no PEM block": []byte("hello"),
	}
	for name, data := range bad {
		if _, err := ParsePrivateKey(data); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

func testKey(t *testing.T, created time.Time) Key {
	t.Helper()
	signer, err := Generate(ES256)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newKey(signer, created, FileName(created))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// backdate gives a key a file name older than its arrival, the way a key
// generated elsewhere or restored from a backup would look.
func backdate(t *testing.T, dir string, created, arrived time.Time) Key {
	t.Helper()
	k, err := Add(t.TempDir(), ES256, created)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalPrivateKey(k.Signer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, k.File)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, arrived, arrived); err != nil {
		t.Fatal(err)
	}
	return k
}

// A process that starts after a backdated key arrived still waits out the
// activation delay, counted from the file's arrival.
func TestLoadDirCountsActivationFromArrival(t *testing.T) {
	dir := t.TempDir()
	current, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	arrived := t0.Add(48 * time.Hour)
	backdate(t, dir, t0.Add(24*time.Hour), arrived)

	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Active(arrived.Add(30*time.Minute), time.Hour); got.ID != current.ID {
		t.Error("a backdated key signs before its activation delay has passed since it arrived")
	}
}

func TestPruneKeepsKeyWhileBackdatedSuccessorActivates(t *testing.T) {
	dir := t.TempDir()
	current, err := Add(dir, ES256, t0)
	if err != nil {
		t.Fatal(err)
	}
	arrived := t0.Add(48 * time.Hour)
	backdate(t, dir, t0.Add(24*time.Hour), arrived)

	removed, err := Prune(dir, arrived, time.Hour, 6*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("Prune removed %d keys, including the signing key %s", len(removed), current.ID)
	}
	removed, err = Prune(dir, arrived.Add(time.Hour+6*time.Minute), time.Hour, 6*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].ID != current.ID {
		t.Fatalf("Prune removed %v after the successor's activation plus retention, want the old key", removed)
	}
}
