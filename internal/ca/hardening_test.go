package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/keyset"
)

// unconstrainedRoot is a self-signed CA with its key that fails the profile.
func unconstrainedRoot(t *testing.T, at time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := key(t)
	return issue(t, profileTemplate(t, k.Public(), "bad root", at, func(c *x509.Certificate) {
		c.MaxPathLen = -1
		c.MaxPathLenZero = false
		c.ExtraExtensions = nil
	}), k.Public(), nil, k), k
}

// A self-signed CA that fails the profile is not an anchor, so a CA that chains
// to it fails too, at startup and while the issuer runs.
func TestRejectedSelfSignedRootIsNeverAnAnchor(t *testing.T) {
	root, rootKey := unconstrainedRoot(t, t0)
	inter := func(dir string, at time.Time) {
		k := key(t)
		install(t, dir, at, k, signIntermediate(t, k.Public(), "under bad root", t0, root, rootKey, nil))
	}

	dir := t.TempDir()
	install(t, dir, t0, rootKey, root)
	inter(dir, t0.Add(time.Hour))
	_, err := Load(testOptions(dir), t0.Add(3*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "CA profile") || !strings.Contains(err.Error(), "does not chain to an anchor") {
		t.Errorf("startup: %v, want both the root and the CA under it refused", err)
	}

	good := t.TempDir()
	first := initRoot(t, good, t0)
	c := &clock{t0.Add(5 * time.Hour)}
	w, err := newWatcher(testOptions(good), quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	install(t, good, t0.Add(time.Hour), rootKey, root)
	inter(good, t0.Add(2*time.Hour))
	w.Reload()
	set, _, _ := w.Current()
	for _, a := range set.Anchors() {
		if a.Cert.Equal(root) {
			t.Fatal("the rejected root is published")
		}
	}
	later := c.t.Add(10 * delay)
	if len(set.CAs()) != 1 || signingFile(t, set, later) != first.File {
		t.Errorf("%d CAs, signing %s: only the good root should be in service", len(set.CAs()), signingFile(t, set, later))
	}
}

// A CA retention has retired is not an anchor any more, so nothing signs with
// it, even when the newer CA's chain is about to end.
func TestSelectNeverUsesARetiredCA(t *testing.T) {
	dir := t.TempDir()
	initRoot(t, dir, t0)
	k := key(t)
	created := t0.Add(time.Hour)
	newer := issue(t, profileTemplate(t, k.Public(), "newer", created, func(c *x509.Certificate) {
		c.NotAfter = t0.Add(24*time.Hour + 30*time.Minute)
	}), k.Public(), nil, k)
	install(t, dir, created, k, newer)

	now := t0.Add(24 * time.Hour)
	set, err := Load(testOptions(dir), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Retired()) != 1 || len(set.Anchors()) != 1 {
		t.Fatalf("%d retired, %d published: the older root should be gone", len(set.Retired()), len(set.Anchors()))
	}
	choice, err := set.Select(now, time.Hour)
	if err != nil || choice.CA.Cert.Equal(set.Retired()[0].Cert) || !choice.Shortened {
		t.Errorf("selected %s (shortened %v, %v): want the newer CA with a shorter certificate", choice.CA.File, choice.Shortened, err)
	}
	now = t0.Add(24*time.Hour + 26*time.Minute)
	if _, err := set.Select(now, time.Hour); !errors.Is(err, ErrExpiring) {
		t.Errorf("4 minutes left on the only published CA: %v, want ErrExpiring", err)
	}
	if _, ok := set.Signing(now); !ok {
		t.Error("nothing signs, but the newer CA is valid")
	}
}

// A root added to ca_roots at the same time as its intermediate must not sign
// at a restart within the delay, whatever the intermediate's file name says.
func TestRestartAfterRootsEditWaitsForTheNewRoot(t *testing.T) {
	dir := t.TempDir()
	rootsPath := filepath.Join(t.TempDir(), "roots.pem")
	r1, r1k := operatorRoot(t, t0, true)
	k1 := key(t)
	install(t, dir, t0, k1, signIntermediate(t, k1.Public(), "i1", t0, r1, r1k, nil))

	csrAt := t0.Add(48 * time.Hour)
	now := t0.Add(10 * 24 * time.Hour)
	r2, r2k := operatorRoot(t, now.Add(-10*time.Minute), true)
	k2 := key(t)
	install(t, dir, csrAt, k2, signIntermediate(t, k2.Public(), "i2", now.Add(-5*time.Minute), r2, r2k, nil))
	touch(t, dir, now.Add(-time.Minute), CertFileName(csrAt))
	writeRoots(t, rootsPath, now.Add(-2*time.Minute), r1, r2)

	opts := testOptions(dir)
	opts.Roots = rootsPath
	set, err := Load(opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := signingFile(t, set, now); got != CertFileName(t0) {
		t.Errorf("signing with %s two minutes after a new root was added, want the old intermediate", got)
	}
	if got := signingFile(t, set, now.Add(delay)); got != CertFileName(csrAt) {
		t.Errorf("signing with %s once the new root has been published for the delay", got)
	}
}

// Removing the key of an intermediate in service stops it, as for a root.
func TestRemovedIntermediateKeyStopsSigning(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	first := newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
	second := newIntermediate(t, opts, t0.Add(2*time.Hour), root, rootKey, nil)

	c := &clock{t0.Add(5 * time.Hour)}
	w, err := newWatcher(opts, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, second.KeyFile)); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	set, _, _ := w.Current()
	if got := signingFile(t, set, c.t); got != first.File {
		t.Errorf("signing with %s after the newer key was removed, want %s", got, first.File)
	}
	if len(set.CAs()) != 1 {
		t.Errorf("%d CAs in service, want the one that still has its key", len(set.CAs()))
	}
}

func TestSubjectMustDifferBetweenGenerations(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	same := func(c *x509.Certificate) { c.RawSubject = mustName(t, "example.org", "the same name") }
	k1, k2 := key(t), key(t)
	install(t, dir, t0.Add(time.Hour), k1, signIntermediate(t, k1.Public(), "", t0, root, rootKey, same))
	if _, err := Load(opts, t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	install(t, dir, t0.Add(2*time.Hour), k2, signIntermediate(t, k2.Public(), "", t0.Add(time.Hour), root, rootKey, same))
	_, err := Load(opts, t0.Add(3*time.Hour))
	if err == nil || !strings.Contains(err.Error(), CertFileName(t0.Add(2*time.Hour))) || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("two generations with one subject: %v, want the newer refused", err)
	}

	// A running issuer keeps the older one and does not use the newer.
	c := &clock{t0.Add(3 * time.Hour)}
	os.Remove(filepath.Join(dir, CertFileName(t0.Add(2*time.Hour))))
	w, err := newWatcher(opts, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	install(t, dir, t0.Add(2*time.Hour), k2, signIntermediate(t, k2.Public(), "", t0.Add(time.Hour), root, rootKey, same))
	w.Reload()
	if set, _, _ := w.Current(); len(set.CAs()) != 1 {
		t.Errorf("%d CAs in service, want only the first", len(set.CAs()))
	}

	// The same key may be certified again under the same name.
	renewed := t.TempDir()
	install(t, renewed, t0.Add(time.Hour), k1, signIntermediate(t, k1.Public(), "", t0, root, rootKey, same))
	install(t, renewed, t0.Add(2*time.Hour), k1, signIntermediate(t, k1.Public(), "", t0.Add(time.Hour), root, rootKey, same))
	opts.Dir = renewed
	if _, err := Load(opts, t0.Add(3*time.Hour)); err != nil {
		t.Errorf("a renewal with the same key and name: %v", err)
	}
}

// Section 2.5.1: a root has the full constraints or is dedicated.
func TestRootNeedsTheFullConstraintsOrIsDedicated(t *testing.T) {
	partial := func(c *x509.Certificate) {
		permitted, excluded := wantedConstraints(td)
		der, err := marshalNameConstraints(permitted, excluded[:1])
		if err != nil {
			t.Fatal(err)
		}
		c.ExtraExtensions = []pkix.Extension{{Id: oidNameConstraints, Critical: true, Value: der}}
	}
	k := key(t)
	root := issue(t, profileTemplate(t, k.Public(), "partial", t0, func(c *x509.Certificate) {
		c.MaxPathLen = -1
		c.MaxPathLenZero = false
		partial(c)
	}), k.Public(), nil, k)
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	if _, err := Load(opts, t0); err == nil || !strings.Contains(err.Error(), "full name constraints") {
		t.Errorf("a root that permits and excludes only some: %v", err)
	}
	initRoot(t, dir, t0)
	if _, err := Load(opts, t0); err == nil {
		t.Error("the partial root was accepted next to a good CA")
	}
	opts.RootsDedicated = true
	if _, err := Load(opts, t0); err != nil {
		t.Errorf("dedicated: %v", err)
	}
}

func TestImportNamesTheBrokenRootsFile(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots
	// A broken generation sorts before the request, and the roots file breaks.
	if err := os.WriteFile(filepath.Join(dir, CertFileName(t0)), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, csr, err := NewCSR(dir, td, keyset.ES256, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := parseCSR(t, csr)
	signed := certificatePEM(signIntermediate(t, req.PublicKey, "x", t0, root, rootKey, func(c *x509.Certificate) { c.RawSubject = req.RawSubject }))
	if err := os.WriteFile(roots, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(opts, signed, t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), roots) {
		t.Errorf("err = %v, want one naming %s", err, roots)
	}
}

// A root that left the bundle and returns because a CA appeared under it is
// published afresh: verifiers may have dropped it.
func TestRevivedRootWaitsOutTheDelay(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	r1, k1 := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, r1)
	opts := testOptions(dir)
	opts.Roots = roots
	newIntermediate(t, opts, t0.Add(time.Hour), r1, k1, nil)
	r2, k2 := operatorRoot(t, t0.Add(10*time.Hour), true)
	writeRoots(t, roots, t0.Add(10*time.Hour), r1, r2)
	second := newIntermediate(t, opts, t0.Add(11*time.Hour), r2, k2, nil)

	c := &clock{t0.Add(12 * time.Hour)}
	w, err := newWatcher(opts, quietLogger(), c.now)
	if err != nil {
		t.Fatal(err)
	}
	c.t = t0.Add(13 * time.Hour)
	w.Reload()
	set, _, _ := w.Current()
	if len(set.Anchors()) != 1 {
		t.Fatalf("%d anchors, want the first root retired", len(set.Anchors()))
	}

	third := newIntermediate(t, opts, c.t, r1, k1, nil)
	c.t = c.t.Add(time.Minute)
	if !w.Reload() {
		t.Fatal("the returning root was not noticed")
	}
	set, _, _ = w.Current()
	if len(set.Anchors()) != 2 {
		t.Fatalf("%d anchors, want the returning root published", len(set.Anchors()))
	}
	if got := signingFile(t, set, c.t); got != second.File {
		t.Errorf("signing with %s the minute the root returns, want %s", got, second.File)
	}
	if got := signingFile(t, set, c.t.Add(delay)); got != third.File {
		t.Errorf("signing with %s once the root has been published again for the delay, want %s", got, third.File)
	}
}

// The newest CA is the one signed last, not the one requested last.
func TestImportOrderDecidesWhichIsNewest(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	request := func(at time.Time) (*x509.CertificateRequest, string) {
		name, csr, err := NewCSR(dir, td, keyset.ES256, at)
		if err != nil {
			t.Fatal(err)
		}
		return parseCSR(t, csr), strings.TrimSuffix(name, ".key") + ".crt"
	}
	first, firstFile := request(t0.Add(time.Hour))
	second, secondFile := request(t0.Add(2 * time.Hour))
	install := func(req *x509.CertificateRequest, signedAt time.Time) {
		cert := signIntermediate(t, req.PublicKey, "x", signedAt, root, rootKey, func(c *x509.Certificate) { c.RawSubject = req.RawSubject })
		if _, err := Import(opts, certificatePEM(cert), signedAt); err != nil {
			t.Fatal(err)
		}
	}
	install(second, t0.Add(3*time.Hour))
	install(first, t0.Add(10*time.Hour))
	touch(t, dir, t0.Add(3*time.Hour), secondFile)
	touch(t, dir, t0.Add(10*time.Hour), firstFile)
	now := t0.Add(12 * time.Hour)
	set, err := Load(opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := signingFile(t, set, now); got != firstFile {
		t.Errorf("signing with %s, want %s: it was signed last", got, firstFile)
	}
}

func TestMoreProfileRefusals(t *testing.T) {
	bc, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{true, 0})
	if err != nil {
		t.Fatal(err)
	}
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := NameConstraints(td)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	with := func(extra ...pkix.Extension) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.ExtraExtensions = append([]pkix.Extension{nc}, extra...) }
	}
	cases := []struct {
		name string
		key  *ecdsa.PrivateKey
		mod  func(*x509.Certificate)
		want string
	}{
		{"basicConstraints not critical", nil, with(pkix.Extension{Id: oidBasicConstraints, Value: bc}), "basicConstraints"},
		{"keyUsage not critical", nil, with(pkix.Extension{Id: oidKeyUsage, Value: ku}), "keyUsage"},
		{"an unknown critical extension", nil, with(pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}), "critical extension"},
		{"a P-384 key signed with SHA-256", p384, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA256 }, "self-signed with"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			k := c.key
			if k == nil {
				k = key(t)
			}
			cert := issue(t, profileTemplate(t, k.Public(), "test "+c.name, t0, c.mod), k.Public(), nil, k)
			install(t, dir, t0, k, cert)
			if _, err := Load(testOptions(dir), t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}

	t.Run("a subtree with a minimum", func(t *testing.T) {
		base := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagURI, Bytes: []byte("example.org")}
		min := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: []byte{1}}
		subtree, err := asn1.Marshal(struct{ Base, Min asn1.RawValue }{base, min})
		if err != nil {
			t.Fatal(err)
		}
		permitted, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: subtree})
		if err != nil {
			t.Fatal(err)
		}
		der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: permitted})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseNameConstraints(der); err == nil {
			t.Error("a subtree with a minimum was read")
		}
	})

	t.Run("a middle CA signed with RSASSA-PSS", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		root := issue(t, profileTemplate(t, rk.Public(), "rsa root", t0, func(c *x509.Certificate) { c.MaxPathLen = -1; c.MaxPathLenZero = false }), rk.Public(), nil, rk)
		mk := key(t)
		middle := issue(t, profileTemplate(t, mk.Public(), "middle", t0, func(c *x509.Certificate) {
			c.MaxPathLen = 1
			c.MaxPathLenZero = false
			c.ExtraExtensions = nil
			c.SignatureAlgorithm = x509.SHA256WithRSAPSS
		}), mk.Public(), root, rk)
		dir := t.TempDir()
		roots := filepath.Join(t.TempDir(), "roots.pem")
		writeRoots(t, roots, t0, root)
		sk := key(t)
		install(t, dir, t0, sk, signIntermediate(t, sk.Public(), "leafward", t0, middle, mk, nil), middle)
		opts := testOptions(dir)
		opts.Roots = roots
		if _, err := Load(opts, t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "RSASSA-PSS") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("an RSA root with a P-384 intermediate", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		root := issue(t, profileTemplate(t, rk.Public(), "rsa root", t0, func(c *x509.Certificate) { c.MaxPathLen = -1; c.MaxPathLenZero = false }), rk.Public(), nil, rk)
		dir := t.TempDir()
		roots := filepath.Join(t.TempDir(), "roots.pem")
		writeRoots(t, roots, t0, root)
		install(t, dir, t0, p384, signIntermediate(t, p384.Public(), "p384", t0, root, rk, nil))
		opts := testOptions(dir)
		opts.Roots = roots
		set, err := Load(opts, t0.Add(time.Hour))
		if err != nil || set.CAs()[0].Algorithm() != "P-384" {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a root signed with RSASSA-PSS", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		root := issue(t, profileTemplate(t, rk.Public(), "pss root", t0, func(c *x509.Certificate) {
			c.MaxPathLen = -1
			c.MaxPathLenZero = false
			c.SignatureAlgorithm = x509.SHA256WithRSAPSS
		}), rk.Public(), nil, rk)
		roots := filepath.Join(t.TempDir(), "roots.pem")
		writeRoots(t, roots, t0, root)
		dir := t.TempDir()
		initRoot(t, dir, t0)
		opts := testOptions(dir)
		opts.Roots = roots
		if _, err := Load(opts, t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "RSASSA-PSS") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestCertificateFileLimits(t *testing.T) {
	c := initRoot(t, t.TempDir(), t0)
	one := certificatePEM(c.Cert)
	if _, err := parseCertificates(slices.Concat(slices.Repeat([][]byte{one}, maxChainLength+1)...), maxChainLength); err == nil {
		t.Error("more certificates than a chain file may hold were read")
	}
	if _, err := parseCertificates(slices.Concat(slices.Repeat([][]byte{one}, maxChainLength)...), maxChainLength); err != nil {
		t.Errorf("a full chain file: %v", err)
	}
	if _, err := parseCertificates(slices.Concat(slices.Repeat([][]byte{one}, maxRoots+1)...), maxRoots); err == nil {
		t.Error("more roots than ca_roots may hold were read")
	}
}

// The race detector's job: readers use a set while reloads replace it.
func TestConcurrentReloadAndUse(t *testing.T) {
	dir := t.TempDir()
	initRoot(t, dir, t0)
	w, err := newWatcher(testOptions(dir), quietLogger(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	w.CheckNewKeys(func(string) error { return nil })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				set, _, _ := w.Current()
				_, _ = set.Select(time.Now(), time.Hour)
				_ = set.Anchors()
			}
		}()
	}
	for i := range 30 {
		if i == 10 {
			initRoot(t, dir, t0.Add(time.Hour))
		}
		w.Reload()
	}
	close(stop)
	wg.Wait()
}

// OpenSSL agrees with Go and go-spiffe that the fence holds for SPIFFE IDs,
// DNS names and addresses. It does not enforce the excluded mailbox subtree
// against email SANs, which is why verifiers must take identity from the URI
// SAN alone (SPEC section 10); that is documented, not asserted here.
func TestOpenSSLEnforcesTheFence(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	dir := t.TempDir()
	now := time.Now()
	c := initRoot(t, dir, now.Add(-time.Hour))
	cases := []struct {
		name string
		id   string
		mod  func(*x509.Certificate)
		ok   bool
	}{
		{"the trust domain", "spiffe://example.org/ns/a", nil, true},
		{"another trust domain", "spiffe://other.org/x", nil, false},
		{"a subdomain", "spiffe://a.example.org/x", nil, false},
		{"a DNS name", "spiffe://example.org/x", func(l *x509.Certificate) { l.DNSNames = []string{"evil.example"} }, false},
		{"an IPv4 address", "spiffe://example.org/x", func(l *x509.Certificate) { l.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")} }, false},
		{"an IPv6 address", "spiffe://example.org/x", func(l *x509.Certificate) { l.IPAddresses = []net.IP{net.ParseIP("::1")} }, false},
	}
	for _, tc := range cases {
		l, _ := leaf(t, tc.id, now, c, tc.mod)
		path := filepath.Join(dir, "leaf.pem")
		if err := os.WriteFile(path, certificatePEM(l), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(openssl, "verify", "-x509_strict", "-CAfile", filepath.Join(dir, c.File), "-purpose", "sslclient", path).CombinedOutput()
		if (err == nil) != tc.ok {
			t.Errorf("%s: openssl verify: %v\n%s", tc.name, err, out)
		}
	}
}
