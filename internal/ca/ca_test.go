package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/keyset"
)

func ids(anchors []Anchor) []string {
	var out []string
	for _, a := range anchors {
		out = append(out, a.ID)
	}
	slices.Sort(out)
	return out
}

func signingFile(t *testing.T, set *Set, now time.Time) string {
	t.Helper()
	c, ok := set.Signing(now)
	if !ok {
		t.Fatalf("nothing signs at %s", now)
	}
	return c.File
}

func TestLoadRoot(t *testing.T) {
	dir := t.TempDir()
	c := initRoot(t, dir, t0)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(testOptions(dir), t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cas := set.CAs()
	if len(cas) != 1 || cas[0].ID != c.ID || !cas[0].SelfSigned() || cas[0].Algorithm() != "P-256" || len(cas[0].Chain) != 1 {
		t.Fatalf("CAs = %+v", cas)
	}
	if a := set.Anchors(); len(a) != 1 || a[0].ID != c.ID || a[0].Source != c.File {
		t.Errorf("anchors = %+v, want the root itself", a)
	}
	if _, err := Load(testOptions(t.TempDir()), t0); err == nil || !strings.Contains(err.Error(), "no CA with a key") {
		t.Errorf("empty directory: %v", err)
	}
}

// A request waits for its certificate, and a certificate without a key is
// no CA.
func TestPendingAndKeylessFiles(t *testing.T) {
	dir := t.TempDir()
	initRoot(t, dir, t0)
	keyFile, _, err := NewCSR(dir, td, keyset.ES256, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := Pending(dir)
	if err != nil || !slices.Equal(pending, []string{keyFile}) {
		t.Fatalf("pending = %v, %v", pending, err)
	}
	if _, err := Load(testOptions(dir), t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("a pending key stopped the load: %v", err)
	}

	// An intermediate certificate with no key is skipped with a warning:
	// nothing could sign with it, and it is how a compromised key is stopped.
	root, rootKey := operatorRoot(t, t0, true)
	k := key(t)
	inter := signIntermediate(t, k.Public(), "inter", t0, root, rootKey, nil)
	install(t, dir, t0.Add(3*time.Hour), nil, inter)
	var warnings []string
	skipOpts := testOptions(dir)
	skipOpts.Warn = func(m string) { warnings = append(warnings, m) }
	set, err := Load(skipOpts, t0.Add(4*time.Hour))
	if err != nil || len(set.CAs()) != 1 {
		t.Errorf("a keyless intermediate: %v", err)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "has no key file") || strings.Contains(warnings[0], "list the root") || !strings.Contains(warnings[1], "signs now") {
		t.Errorf("warnings = %v", warnings)
	}
	// A key that is not the certificate's is refused.
	install(t, dir, t0.Add(3*time.Hour), key(t), inter)
	if _, err := Load(testOptions(dir), t0.Add(4*time.Hour)); err == nil || !strings.Contains(err.Error(), "does not hold the key") {
		t.Errorf("err = %v", err)
	}
	// A self-signed certificate with no key is an anchor and nothing more.
	other := t.TempDir()
	c := initRoot(t, other, t0)
	if err := os.Remove(filepath.Join(other, c.KeyFile)); err != nil {
		t.Fatal(err)
	}
	// With no CA left that has a key but an anchor published, startup warns
	// and goes on with no signing CA; with nothing at all it fails.
	warnings = nil
	if set, err := Load(skipOpts2(other, &warnings), t0.Add(4*time.Hour)); err != nil || len(set.CAs()) != 0 || len(set.Anchors()) != 1 || len(warnings) != 1 {
		t.Errorf("anchor only: %v, %d warnings", err, len(warnings))
	}
	if _, err := Load(testOptions(t.TempDir()), t0.Add(4*time.Hour)); err == nil || !strings.Contains(err.Error(), "no CA with a key") {
		t.Errorf("err = %v", err)
	}
	signer := t.TempDir()
	initRoot(t, signer, t0.Add(time.Hour))
	data, err := os.ReadFile(filepath.Join(other, c.File))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(signer, c.File), data, 0o644); err != nil {
		t.Fatal(err)
	}
	set, err = Load(testOptions(signer), t0.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.CAs()) != 1 || len(set.Anchors()) != 2 {
		t.Errorf("%d CAs and %d anchors, want one CA and two anchors", len(set.CAs()), len(set.Anchors()))
	}
}

// Section 2.5: a new anchor is published before anything chaining to it is
// issued, and kept after the last use.
func TestRootRotation(t *testing.T) {
	dir := t.TempDir()
	a := initRoot(t, dir, t0)
	b := initRoot(t, dir, t0.Add(10*time.Hour))
	load := func(now time.Time) *Set {
		set, err := Load(testOptions(dir), now)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}

	set := load(t0.Add(10*time.Hour + 30*time.Minute))
	if got := signingFile(t, set, t0.Add(10*time.Hour+30*time.Minute)); got != a.File {
		t.Errorf("signing with %s while the new root is half published, want %s", got, a.File)
	}
	if !slices.Equal(ids(set.Anchors()), ids([]Anchor{{ID: a.ID}, {ID: b.ID}})) {
		t.Errorf("the new root is not published before it is used")
	}

	activation := t0.Add(11 * time.Hour)
	if got := signingFile(t, load(activation), activation); got != b.File {
		t.Errorf("signing with %s once the new root is activated, want %s", got, b.File)
	}
	if got := signingFile(t, load(activation), activation.Add(-time.Second)); got != a.File {
		t.Errorf("signing with %s a second before, want %s", got, a.File)
	}

	// The old root stays published for the retention after its last use.
	before := activation.Add(retention - time.Second)
	set = load(before)
	if len(set.Anchors()) != 2 || len(set.Retired()) != 0 {
		t.Errorf("at %s: %d anchors, %d retired; the old root is dropped too early", before, len(set.Anchors()), len(set.Retired()))
	}
	after := activation.Add(retention)
	set = load(after)
	if got := ids(set.Anchors()); !slices.Equal(got, []string{b.ID}) {
		t.Errorf("anchors after retention = %v, want only the new root", got)
	}
	if r := set.Retired(); len(r) != 1 || r[0].ID != a.ID {
		t.Errorf("retired = %+v", r)
	}
	if len(set.AllAnchors()) != 2 || !set.AnchorRetired(set.AllAnchors()[0]) && !set.AnchorRetired(set.AllAnchors()[1]) {
		t.Error("the retired anchor is not reported as retired")
	}
}

// After a restart every file looks new if a Secret update rewrote them all;
// the CA that was signing before goes on signing.
func TestActivationFallbackAfterRestart(t *testing.T) {
	dir := t.TempDir()
	a := initRoot(t, dir, t0)
	b := initRoot(t, dir, t0.Add(10*time.Hour))
	restart := t0.Add(10*time.Hour + 30*time.Minute)
	touch(t, dir, restart, a.File, a.KeyFile, b.File, b.KeyFile)

	set, err := Load(testOptions(dir), restart.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := signingFile(t, set, restart.Add(time.Minute)); got != a.File {
		t.Errorf("signing with %s, want the older %s: the newer one is named for half an hour ago", got, a.File)
	}
	later := t0.Add(20 * time.Hour)
	touch(t, dir, later, a.File, a.KeyFile, b.File, b.KeyFile)
	if set, err = Load(testOptions(dir), later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := signingFile(t, set, later.Add(time.Minute)); got != b.File {
		t.Errorf("signing with %s, want the newer %s: both are named for hours ago", got, b.File)
	}
	// Brand new trust domain: nothing is old enough, so the oldest signs.
	fresh := t.TempDir()
	x := initRoot(t, fresh, t0)
	initRoot(t, fresh, t0.Add(time.Minute))
	set, err = Load(testOptions(fresh), t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := signingFile(t, set, t0.Add(2*time.Minute)); got != x.File {
		t.Errorf("signing with %s, want the oldest %s", got, x.File)
	}
}

func parseCSR(t *testing.T, data []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a certificate request: %q", data)
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return req
}

// newIntermediate does what an operator does: request a signing CA, have the
// operator's CA sign it, and install it, all at the given time. middles are
// the CA certificates between the operator's signer and the anchor.
func newIntermediate(t *testing.T, opts Options, at time.Time, signer *x509.Certificate, signerKey crypto.Signer, mod func(*x509.Certificate), middles ...*x509.Certificate) CA {
	t.Helper()
	_, csr, err := NewCSR(opts.Dir, td, keyset.ES256, at)
	if err != nil {
		t.Fatal(err)
	}
	req := parseCSR(t, csr)
	cert := signIntermediate(t, req.PublicKey, "ignored", at, signer, signerKey, func(c *x509.Certificate) {
		c.RawSubject = req.RawSubject
		if mod != nil {
			mod(c)
		}
	})
	c, err := Import(opts, certificatePEM(append([]*x509.Certificate{cert}, middles...)...), at)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, opts.Dir, at, c.File)
	return c
}

func TestIntermediateUnderOperatorRoot(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	_, csr, err := NewCSR(dir, td, keyset.ES256, t0.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if req := parseCSR(t, csr); len(req.Extensions) < 3 {
		t.Errorf("the request carries %d extensions, want the profile's", len(req.Extensions))
	}
	c := newIntermediate(t, opts, t0.Add(5*time.Hour), root, rootKey, nil)
	if c.SelfSigned() || !c.Anchor.Equal(root) || len(c.Chain) != 1 {
		t.Fatalf("imported CA: anchor %v, chain of %d", c.Anchor.Subject, len(c.Chain))
	}

	now := t0.Add(5*time.Hour + time.Minute)
	set, err := Load(opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(set.Anchors()); len(got) != 1 || got[0] != certID(root) {
		t.Errorf("anchors = %v, want only the operator's root: the bundle does not hold the intermediate", got)
	}
	if got := signingFile(t, set, now); got != c.File {
		t.Errorf("signing with %s: an intermediate under a root published for hours signs at once", got)
	}

	choice, err := set.Select(now, svidTTL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	middle := x509.NewCertPool()
	middle.AddCert(choice.CA.Cert)
	verify := func(l *x509.Certificate) error {
		_, err := l.Verify(x509.VerifyOptions{Roots: pool, Intermediates: middle, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	good, _ := leaf(t, "spiffe://example.org/ns/shop", time.Now(), choice.CA, nil)
	if err := verify(good); err != nil {
		t.Errorf("a leaf does not verify against the operator's root: %v", err)
	}
	chain := [][]byte{good.Raw}
	for _, cert := range choice.CA.Chain {
		chain = append(chain, cert.Raw)
	}
	if _, _, err := x509svid.ParseAndVerify(chain, x509bundle.FromX509Authorities(td, []*x509.Certificate{root})); err != nil {
		t.Errorf("go-spiffe: %v", err)
	}
	for _, id := range []string{"spiffe://other.org/x", "spiffe://sub.example.org/x"} {
		forged, _ := leaf(t, id, time.Now(), choice.CA, nil)
		if verify(forged) == nil {
			t.Errorf("a leaf for %s verifies against the operator's root", id)
		}
	}
}

func TestOperatorRootsMustFenceOrBeDedicated(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, false)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	if _, err := Load(opts, t0); err == nil || !strings.Contains(err.Error(), "ca_roots_dedicated") {
		t.Errorf("a root without name constraints and not dedicated: %v", err)
	}
	opts.RootsDedicated = true
	newIntermediate(t, opts, t0.Add(time.Hour), root, rootKey, nil)
	if _, err := Load(opts, t0.Add(3*time.Hour)); err != nil {
		t.Errorf("a dedicated root: %v", err)
	}

	// A root that fences some other trust domain does not count.
	otherFence, err := NameConstraints(spiffeid.RequireTrustDomainFromString("other.org"))
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := key(t)
	wrong := issue(t, profileTemplate(t, wrongKey.Public(), "other", t0, func(c *x509.Certificate) {
		c.MaxPathLen = -1
		c.MaxPathLenZero = false
		c.ExtraExtensions = []pkix.Extension{otherFence}
	}), wrongKey.Public(), nil, wrongKey)
	writeRoots(t, roots, t0, wrong)
	opts.RootsDedicated = false
	if _, err := Load(opts, t0); err == nil || !strings.Contains(err.Error(), "ca_roots_dedicated") {
		t.Errorf("a root fencing another trust domain: %v", err)
	}

	// Roots are roots: a certificate that is not self-signed, a leaf and a
	// private key are refused.
	root2, rootKey2 := operatorRoot(t, t0, true)
	sub := signIntermediate(t, key(t).Public(), "sub", t0, root2, rootKey2, nil)
	writeRoots(t, roots, t0, sub)
	if _, err := Load(opts, t0); err == nil || !strings.Contains(err.Error(), "not self-signed") {
		t.Errorf("an intermediate in ca_roots: %v", err)
	}
	keyPEM, err := keyset.MarshalPrivateKey(key(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots, append(certificatePEM(root2), keyPEM...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(opts, t0); err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("a private key in ca_roots: %v", err)
	}
	if err := os.WriteFile(roots, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(opts, t0); err == nil {
		t.Error("an empty ca_roots was accepted")
	}
	if err := os.Remove(roots); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(opts, t0); err == nil {
		t.Error("a missing ca_roots was accepted")
	}
}

func TestChainThroughMiddleCAs(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	mk := key(t)
	middle := issue(t, profileTemplate(t, mk.Public(), "middle", t0, func(c *x509.Certificate) {
		c.MaxPathLen = 1
		c.MaxPathLenZero = false
		c.ExtraExtensions = nil
	}), mk.Public(), root, rootKey)
	c := newIntermediate(t, opts, t0.Add(time.Hour), middle, mk, nil, middle)
	if len(c.Chain) != 2 || !c.Chain[1].Equal(middle) || !c.Anchor.Equal(root) {
		t.Fatalf("chain of %d, anchor %v: want the signing CA, the middle CA, and the root as anchor", len(c.Chain), c.Anchor.Subject)
	}
	set, err := Load(opts, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(set.Anchors()); len(got) != 1 || got[0] != certID(root) {
		t.Errorf("anchors = %v", got)
	}

	// The middle CA missing from the file, or unrelated, or too short a
	// path length, refuse the chain.
	_, csr, err := NewCSR(dir, td, keyset.ES256, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := parseCSR(t, csr)
	inter := signIntermediate(t, req.PublicKey, "x", t0, middle, mk, func(c *x509.Certificate) { c.RawSubject = req.RawSubject })
	if _, err := Import(opts, certificatePEM(inter), t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Errorf("without the middle CA: %v", err)
	}
	stranger := key(t)
	strangerCert := issue(t, profileTemplate(t, stranger.Public(), "stranger", t0, nil), stranger.Public(), nil, stranger)
	if _, err := Import(opts, certificatePEM(inter, middle, strangerCert), t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "not on the path") {
		t.Errorf("with an unrelated certificate: %v", err)
	}
	narrow := issue(t, profileTemplate(t, mk.Public(), "narrow", t0, func(c *x509.Certificate) { c.ExtraExtensions = nil }), mk.Public(), root, rootKey)
	inter2 := signIntermediate(t, req.PublicKey, "x", t0, narrow, mk, func(c *x509.Certificate) { c.RawSubject = req.RawSubject })
	if _, err := Import(opts, certificatePEM(inter2, narrow), t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Errorf("under a middle CA whose path length is 0: %v", err)
	}
	if got, err := Pending(dir); err != nil || len(got) != 1 {
		t.Errorf("the failed imports left %v (%v), want the one pending key", got, err)
	}
}

func TestImportRefusals(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root, rootKey := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root)
	opts := testOptions(dir)
	opts.Roots = roots

	_, csr, err := NewCSR(dir, td, keyset.ES256, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := parseCSR(t, csr)
	sign := func(mod func(*x509.Certificate)) []byte {
		return certificatePEM(signIntermediate(t, req.PublicKey, "x", t0, root, rootKey, func(c *x509.Certificate) {
			c.RawSubject = req.RawSubject
			if mod != nil {
				mod(c)
			}
		}))
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"a certificate for a key not held here", certificatePEM(signIntermediate(t, key(t).Public(), "x", t0, root, rootKey, nil)), "no key file"},
		{"no name constraints", sign(func(c *x509.Certificate) { c.ExtraExtensions = nil }), "no nameConstraints"},
		{"a path length of 3", sign(func(c *x509.Certificate) { c.MaxPathLen = 3; c.MaxPathLenZero = false }), "pathLenConstraint 0"},
		{"expired", sign(func(c *x509.Certificate) { c.NotAfter = t0.Add(30 * time.Minute) }), "expired"},
		{"not PEM", []byte("garbage"), "no certificate"},
	}
	for _, c := range cases {
		if _, err := Import(opts, c.data, t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one containing %q", c.name, err, c.want)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".crt") {
			t.Errorf("a refused import left %s", e.Name())
		}
	}
	good := sign(nil)
	if _, err := Import(opts, good, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(opts, good, t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "already has its certificate") {
		t.Errorf("a second import: %v", err)
	}
}

// A new intermediate may sign at once under an anchor that has been published
// long enough, but one under a new root waits for that root.
func TestIntermediateActivationFollowsItsAnchor(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	root1, key1 := operatorRoot(t, t0, true)
	writeRoots(t, roots, t0, root1)
	opts := testOptions(dir)
	opts.Roots = roots

	i1 := newIntermediate(t, opts, t0.Add(time.Hour), root1, key1, nil)
	i2 := newIntermediate(t, opts, t0.Add(5*time.Hour), root1, key1, nil)
	at := func(now time.Time) *Set {
		set, err := Load(opts, now)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	if got := signingFile(t, at(t0.Add(5*time.Hour+time.Second)), t0.Add(5*time.Hour+time.Second)); got != i2.File {
		t.Errorf("signing with %s right after the second intermediate arrived, want %s", got, i2.File)
	}
	_ = i1

	// A new root arrives at 20h, its intermediate at 21h.
	root2, key2 := operatorRoot(t, t0.Add(20*time.Hour), true)
	writeRoots(t, roots, t0.Add(20*time.Hour), root1, root2)
	i3 := newIntermediate(t, opts, t0.Add(21*time.Hour), root2, key2, nil)
	soon := t0.Add(20*time.Hour + 30*time.Minute)
	if set := at(soon); signingFile(t, set, soon) != i2.File || len(set.Anchors()) != 2 {
		t.Errorf("before the new root has been published for the delay: signing %s, %d anchors", signingFile(t, set, soon), len(set.Anchors()))
	}
	// The file times say the roots file changed at 20h and the intermediate
	// came at 21h: the delay counts from 20h.
	ready := t0.Add(21 * time.Hour)
	if got := signingFile(t, at(ready), ready); got != i3.File {
		t.Errorf("signing with %s, want %s", got, i3.File)
	}
	// Once retention has passed, the old root goes: the CAs under it are
	// retired, and the new root stays.
	gone := ready.Add(retention)
	set := at(gone)
	if got := ids(set.Anchors()); len(got) != 1 || got[0] != certID(root2) {
		t.Errorf("anchors after retention = %v, want only the new root", got)
	}
	if len(set.Retired()) != 2 {
		t.Errorf("%d retired CAs, want the two under the old root", len(set.Retired()))
	}
	// A root nothing chains to yet stays published, and is not retired.
	root3, _ := operatorRoot(t, t0.Add(30*time.Hour), true)
	writeRoots(t, roots, t0.Add(30*time.Hour), root1, root2, root3)
	if got := ids(at(t0.Add(40 * time.Hour)).Anchors()); len(got) != 2 {
		t.Errorf("anchors = %v, want the new root and the one waiting to be used, not the retired one", got)
	}
}

func TestSelectAndExpiry(t *testing.T) {
	short := func(notAfter time.Time) (CA, *Set) {
		dir := t.TempDir()
		k := key(t)
		cert := issue(t, profileTemplate(t, k.Public(), "short", t0, func(c *x509.Certificate) { c.NotAfter = notAfter }), k.Public(), nil, k)
		install(t, dir, t0, k, cert)
		set, err := Load(testOptions(dir), t0)
		if err != nil {
			t.Fatal(err)
		}
		return set.CAs()[0], set
	}
	_, set := short(t0.Add(90 * time.Minute))

	c, err := set.Select(t0, time.Hour)
	if err != nil || c.Shortened || !c.NotAfter.Equal(t0.Add(time.Hour)) {
		t.Errorf("a chain that outlives the lifetime: %+v, %v", c, err)
	}
	now := t0.Add(45 * time.Minute)
	c, err = set.Select(now, time.Hour)
	if err != nil || !c.Shortened || !c.NotAfter.Equal(t0.Add(90*time.Minute)) {
		t.Errorf("a chain that does not: %+v, %v; want a shorter certificate ending with the chain", c, err)
	}
	now = t0.Add(86 * time.Minute)
	if _, err = set.Select(now, time.Hour); !errors.Is(err, ErrExpiring) {
		t.Errorf("4 minutes left: %v, want ErrExpiring", err)
	}
	if set.Usable(now, time.Hour) {
		t.Error("a CA with 4 minutes left is usable")
	}
	now = t0.Add(85 * time.Minute)
	if _, err = set.Select(now, time.Hour); err != nil {
		t.Errorf("5 minutes left: %v", err)
	}
	now = t0.Add(91 * time.Minute)
	if _, err = set.Select(now, time.Hour); !errors.Is(err, ErrNoSigningCA) {
		t.Errorf("expired: %v, want ErrNoSigningCA", err)
	}
	if got := set.WarnExpiry(t0); len(got) != 1 {
		t.Errorf("warnings = %d, want one for a CA that expires in 90 minutes", len(got))
	}
	_, far := short(t0.Add(365 * 24 * time.Hour))
	if got := far.WarnExpiry(t0); len(got) != 0 {
		t.Errorf("a CA with a year left was warned about")
	}

	// A newer CA whose chain is short signs shorter certificates and then
	// refuses; the older one does not take over from it.
	dir := t.TempDir()
	older := initRoot(t, dir, t0)
	k := key(t)
	newer := issue(t, profileTemplate(t, k.Public(), "newer", t0.Add(time.Hour), func(c *x509.Certificate) { c.NotAfter = t0.Add(3 * time.Hour) }), k.Public(), nil, k)
	install(t, dir, t0.Add(time.Hour), k, newer)
	set, err = Load(testOptions(dir), t0.Add(2*time.Hour+30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	now = t0.Add(2*time.Hour + 30*time.Minute)
	if c, err = set.Select(now, time.Hour); err != nil || c.CA.File == older.File || !c.Shortened || !c.NotAfter.Equal(t0.Add(3*time.Hour)) {
		t.Errorf("selected %s (shortened %v, until %s, %v), want the newer CA with a certificate that ends with its chain", c.CA.File, c.Shortened, c.NotAfter, err)
	}
	early := t0.Add(2*time.Hour + 10*time.Minute)
	if c, err = set.Select(early, 30*time.Minute); err != nil || c.CA.File == older.File || c.Shortened {
		t.Errorf("selected %s (shortened %v, %v), want the newer one while its chain outlasts the lifetime", c.CA.File, c.Shortened, err)
	}
	if _, err = set.Select(t0.Add(2*time.Hour+56*time.Minute), time.Hour); !errors.Is(err, ErrExpiring) {
		t.Errorf("4 minutes left on the newer CA: %v, want ErrExpiring", err)
	}
	now = t0.Add(3*time.Hour + time.Minute)
	if _, err := set.Select(now, time.Hour); !errors.Is(err, ErrNoSigningCA) {
		t.Errorf("once the newer one expired: %v, want ErrNoSigningCA and not the older root", err)
	}
}

func TestPruneAndPending(t *testing.T) {
	dir := t.TempDir()
	a := initRoot(t, dir, t0)
	b := initRoot(t, dir, t0.Add(10*time.Hour))
	opts := testOptions(dir)

	before := t0.Add(11*time.Hour + retention - time.Second)
	if removed, err := Prune(opts, before); err != nil || len(removed) != 0 {
		t.Fatalf("pruned %v too early (%v)", removed, err)
	}
	removed, err := Prune(opts, before.Add(time.Second))
	if err != nil || len(removed) != 1 || removed[0].ID != a.ID {
		t.Fatalf("pruned %v (%v), want the first root", removed, err)
	}
	for _, name := range []string{a.File, a.KeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed (%v)", name, err)
		}
	}
	for _, name := range []string{b.File, b.KeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func skipOpts2(dir string, warnings *[]string) Options {
	opts := testOptions(dir)
	opts.Warn = func(m string) { *warnings = append(*warnings, m) }
	return opts
}
