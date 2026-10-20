package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// leafFixture is a root of example.org that may sign now.
func leafFixture(t *testing.T) (dir string, now time.Time, set *Set, choice Choice) {
	t.Helper()
	dir = t.TempDir()
	now = time.Now().Truncate(time.Second)
	initRoot(t, dir, now.Add(-48*time.Hour))
	var err error
	if set, err = Load(testOptions(dir), now); err != nil {
		t.Fatal(err)
	}
	if choice, err = set.Select(now, time.Hour); err != nil {
		t.Fatal(err)
	}
	return dir, now, set, choice
}

func rawExtensions(cert *x509.Certificate) map[string]pkix.Extension {
	out := map[string]pkix.Extension{}
	for _, e := range cert.Extensions {
		out[e.Id.String()] = e
	}
	return out
}

// The leaf has the profile of SPEC section 3.4 and nothing else.
func TestIssueLeafProfile(t *testing.T) {
	_, now, _, choice := leafFixture(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromPath(td, "/prod/ns/shop/sa/billing")
	for name, k := range map[string]crypto.Signer{"ECDSA": key(t), "RSA": rsaKey} {
		t.Run(name, func(t *testing.T) {
			leaf, err := IssueLeaf(choice, id, k.Public(), now)
			if err != nil {
				t.Fatal(err)
			}
			wantSubject, err := Name("example.org", id.String())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(leaf.RawSubject, wantSubject) {
				t.Errorf("subject %x, want O=example.org, CN=%s as UTF8Strings", leaf.RawSubject, id)
			}
			if !bytes.Equal(leaf.RawIssuer, choice.CA.Cert.RawSubject) {
				t.Error("issuer is not the CA's subject byte for byte")
			}
			if leaf.SerialNumber.Sign() <= 0 || len(leaf.SerialNumber.Bytes()) > 16 || leaf.SerialNumber.Bit(127) != 0 {
				t.Errorf("serial %x", leaf.SerialNumber)
			}
			if !leaf.NotBefore.Equal(now.Add(-30*time.Second)) || !leaf.NotAfter.Equal(now.Add(time.Hour)) {
				t.Errorf("validity %s to %s", leaf.NotBefore, leaf.NotAfter)
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != id.String() || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
				t.Errorf("names %v %v %v %v", leaf.URIs, leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses)
			}
			wantUsage := x509.KeyUsageDigitalSignature
			if name == "RSA" {
				wantUsage |= x509.KeyUsageKeyEncipherment
			}
			if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != wantUsage {
				t.Errorf("isCA %v, basic constraints valid %v, key usage %v", leaf.IsCA, leaf.BasicConstraintsValid, leaf.KeyUsage)
			}
			if len(leaf.ExtKeyUsage) != 2 || len(leaf.UnknownExtKeyUsage) != 0 {
				t.Errorf("extended key usage %v", leaf.ExtKeyUsage)
			}
			ski, _ := SubjectKeyID(k.Public())
			if !bytes.Equal(leaf.SubjectKeyId, ski) || !bytes.Equal(leaf.AuthorityKeyId, choice.CA.Cert.SubjectKeyId) {
				t.Error("subject or authority key identifier")
			}
			exts := rawExtensions(leaf)
			for oid, critical := range map[string]bool{
				"2.5.29.19": true,  // basicConstraints
				"2.5.29.15": true,  // keyUsage
				"2.5.29.17": false, // subjectAltName
				"2.5.29.37": false, // extKeyUsage
				"2.5.29.14": false, // subjectKeyIdentifier
				"2.5.29.35": false, // authorityKeyIdentifier
			} {
				e, ok := exts[oid]
				if !ok || e.Critical != critical {
					t.Errorf("extension %s present %v critical %v, want critical %v", oid, ok, e.Critical, critical)
				}
				delete(exts, oid)
			}
			if len(exts) != 0 {
				t.Errorf("unexpected extensions %v", exts)
			}
			if name == "ECDSA" && leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
				t.Errorf("signed with %s", leaf.SignatureAlgorithm)
			}
		})
	}
}

// The subject leaves out what exceeds RFC 5280's bounds, and the SAN is
// critical exactly when nothing is left.
func TestIssueLeafSubjectBounds(t *testing.T) {
	long := strings.Repeat("a", 40)
	cases := []struct {
		name      string
		td        string
		path      string
		wantO     string
		wantCN    bool
		critical  bool
		wantEmpty bool
	}{
		{"fits", "example.org", "/x", "example.org", true, false, false},
		{"id too long for CN", "example.org", "/" + long + "/" + long, "example.org", false, false, false},
		{"exactly 64", "example.org", "/" + strings.Repeat("a", 64-len("spiffe://example.org/")), "example.org", true, false, false},
		{"trust domain too long for O, and so is the ID for CN", strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + ".org", "/" + long, "", false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().Truncate(time.Second)
			d := spiffeid.RequireTrustDomainFromString(tc.td)
			made, err := Init(dir, d, now.Add(-48*time.Hour), 5*365*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			touch(t, dir, now.Add(-48*time.Hour), made.File, made.KeyFile)
			opts := testOptions(dir)
			opts.TrustDomain = d
			set, err := Load(opts, now)
			if err != nil {
				t.Fatal(err)
			}
			choice, err := set.Select(now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			id := spiffeid.RequireFromPath(d, tc.path)
			leaf, err := IssueLeaf(choice, id, key(t).Public(), now)
			if err != nil {
				t.Fatal(err)
			}
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(leaf.RawSubject, &rdns); err != nil {
				t.Fatal(err)
			}
			var gotO, gotCN string
			for _, rdn := range rdns {
				if len(rdn) != 1 {
					t.Fatalf("an RDN with %d attributes", len(rdn))
				}
				switch s, _ := rdn[0].Value.(string); {
				case rdn[0].Type.Equal(oidOrganization):
					gotO = s
				case rdn[0].Type.Equal(oidCommonName):
					gotCN = s
				}
			}
			if gotO != tc.wantO || (gotCN == id.String()) != tc.wantCN || (!tc.wantCN && gotCN != "") {
				t.Errorf("O=%q CN=%q", gotO, gotCN)
			}
			if tc.wantEmpty != bytes.Equal(leaf.RawSubject, []byte{0x30, 0x00}) {
				t.Errorf("subject %x, empty wanted %v", leaf.RawSubject, tc.wantEmpty)
			}
			if got := rawExtensions(leaf)["2.5.29.17"].Critical; got != tc.critical {
				t.Errorf("SAN critical = %v, want %v", got, tc.critical)
			}
		})
	}
}

// The notAfter of the leaf is the choice's, which the chain bounds.
func TestIssueLeafStopsWithTheChain(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	made, err := Init(dir, td, now.Add(-48*time.Hour), 48*time.Hour+30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, dir, now.Add(-48*time.Hour), made.File, made.KeyFile)
	set, err := Load(testOptions(dir), now)
	if err != nil {
		t.Fatal(err)
	}
	choice, err := set.Select(now, time.Hour)
	if err != nil || !choice.Shortened {
		t.Fatalf("choice %+v, %v", choice, err)
	}
	leaf, err := IssueLeaf(choice, spiffeid.RequireFromPath(td, "/x"), key(t).Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(choice.CA.Cert.NotAfter) {
		t.Errorf("the leaf ends %s, after the CA's %s", leaf.NotAfter, choice.CA.Cert.NotAfter)
	}
}

// A leaf for another trust domain, signed by the CA's own key, is refused by
// the verifier: name constraints are the CA's fence.
func TestNameConstraintsRejectAForgedLeaf(t *testing.T) {
	_, now, set, choice := leafFixture(t)
	roots := x509.NewCertPool()
	for _, a := range set.Anchors() {
		roots.AddCert(a.Cert)
	}
	verify := func(leaf *x509.Certificate) error {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	for _, tc := range []struct {
		id string
		ok bool
	}{
		{"spiffe://example.org/ns/a", true},
		{"spiffe://other.org/ns/a", false},
		{"spiffe://sub.example.org/ns/a", false},
		{"spiffe://example.org.evil.org/ns/a", false},
	} {
		leaf, err := IssueLeaf(choice, spiffeid.RequireFromString(tc.id), key(t).Public(), now)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(leaf); (err == nil) != tc.ok {
			t.Errorf("%s: verify = %v, want ok %v", tc.id, err, tc.ok)
		}
	}
}

// OpenSSL accepts the leaf with CN=spiffe://... and its subject, as client
// and server, strictly; the CA's name constraints apply to the SAN and do not
// reach the common name.
func TestOpenSSLAcceptsTheLeaf(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	dir, now, _, choice := leafFixture(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 70)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		id   string
		key  crypto.Signer
		ok   bool
	}{
		{"P-384", "spiffe://example.org/p384", p384, true},
		{"Ed25519", "spiffe://example.org/ed25519", edKey, true},
		{"ECDSA", "spiffe://example.org/prod/ns/shop/sa/billing", key(t), true},
		{"RSA", "spiffe://example.org/rsa", rsaKey, true},
		{"no common name", "spiffe://example.org/" + long, key(t), true},
		{"another trust domain", "spiffe://other.org/x", key(t), false},
	}
	for _, tc := range cases {
		leaf, err := IssueLeaf(choice, spiffeid.RequireFromString(tc.id), tc.key.Public(), now)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "leaf.pem")
		if err := os.WriteFile(path, certificatePEM(leaf), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, purpose := range []string{"sslclient", "sslserver"} {
			out, err := exec.Command(openssl, "verify", "-x509_strict", "-CAfile", filepath.Join(dir, choice.CA.File), "-purpose", purpose, path).CombinedOutput()
			if (err == nil) != tc.ok {
				t.Errorf("%s as %s: openssl verify: %v\n%s", tc.name, purpose, err, out)
			}
		}
	}
}

// The leaf is never older than the chain that signs it: a CA that became
// valid a few seconds ago gives a leaf that starts with it.
func TestIssueLeafNotBeforeStaysInsideTheChain(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	root, rootKey := operatorRoot(t, now.Add(-time.Hour), true)
	interKey := key(t)
	inter := signIntermediate(t, interKey.Public(), "spiffex CA", now, root, rootKey, func(c *x509.Certificate) {
		c.NotBefore = now.Add(-5 * time.Second)
	})
	choice := Choice{CA: CA{Cert: inter, Chain: []*x509.Certificate{inter}, Anchor: root, Signer: interKey}, NotAfter: now.Add(time.Hour)}
	leaf, err := IssueLeaf(choice, spiffeid.RequireFromPath(td, "/x"), key(t).Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotBefore.Equal(inter.NotBefore) {
		t.Errorf("notBefore %s, want the intermediate's %s", leaf.NotBefore, inter.NotBefore)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inters, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("verify at issue time: %v", err)
	}
}

// Select returns whole seconds, so the floor holds for the certificate as
// issued.
func TestSelectNotAfterIsWholeSeconds(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second).Add(900 * time.Millisecond)
	initRoot(t, dir, now.Add(-48*time.Hour))
	set, err := Load(testOptions(dir), now)
	if err != nil {
		t.Fatal(err)
	}
	choice, err := set.Select(now, time.Hour)
	if err != nil || choice.NotAfter.Nanosecond() != 0 {
		t.Errorf("not after %s, %v", choice.NotAfter, err)
	}
}

// The caller chooses the common name; it is never cut, and none is allowed.
func TestIssueLeafCN(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	made, err := Init(dir, td, now.Add(-48*time.Hour), 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, dir, now.Add(-48*time.Hour), made.File, made.KeyFile)
	opts := testOptions(dir)
	opts.TrustDomain = td
	set, err := Load(opts, now)
	if err != nil {
		t.Fatal(err)
	}
	choice, err := set.Select(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromPath(td, "/x/y")
	for _, cn := range []string{"/x/y", "x/y", strings.Repeat("a", MaxNameLength), ""} {
		leaf, err := IssueLeafCN(choice, id, cn, key(t).Public(), now)
		if err != nil {
			t.Fatalf("%q: %v", cn, err)
		}
		if leaf.Subject.CommonName != cn {
			t.Errorf("CN %q, want %q", leaf.Subject.CommonName, cn)
		}
		if len(leaf.Subject.Organization) != 1 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != id.String() {
			t.Errorf("subject %v, URIs %v", leaf.Subject, leaf.URIs)
		}
	}
	if _, err := IssueLeafCN(choice, id, strings.Repeat("a", MaxNameLength+1), key(t).Public(), now); err == nil {
		t.Error("a common name of 65 characters was accepted")
	}
}
