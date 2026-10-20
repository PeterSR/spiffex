package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/keyset"
)

var (
	t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	td = spiffeid.RequireTrustDomainFromString("example.org")
)

const (
	delay     = time.Hour
	svidTTL   = time.Hour
	retention = svidTTL + ClockSkew
)

func testOptions(dir string) Options {
	return Options{Dir: dir, TrustDomain: td, ActivationDelay: delay, Retention: retention}
}

// touch sets the modification time of the files of a CA generation, which
// loading counts publication from.
func touch(t *testing.T, dir string, at time.Time, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.Chtimes(filepath.Join(dir, name), at, at); err != nil {
			t.Fatal(err)
		}
	}
}

// initRoot makes a self-signed root as spiffex ca init does, made and
// delivered at the given time.
func initRoot(t *testing.T, dir string, at time.Time) CA {
	t.Helper()
	c, err := Init(dir, td, at, 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	touch(t, dir, at, c.File, c.KeyFile)
	return c
}

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := SerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustName(t *testing.T, org, cn string) []byte {
	t.Helper()
	n, err := Name(org, cn)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// profileTemplate is a certificate that meets the profile of SPEC section
// 2.5, for the key pub, to be changed by mod.
func profileTemplate(t *testing.T, pub crypto.PublicKey, cn string, at time.Time, mod func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	ski, err := SubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := NameConstraints(td)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{
		SerialNumber:          serial(t),
		RawSubject:            mustName(t, td.Name(), cn),
		NotBefore:             at.Add(-time.Minute),
		NotAfter:              at.Add(5 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
		ExtraExtensions:       []pkix.Extension{nc},
	}
	if mod != nil {
		mod(c)
	}
	return c
}

// issue signs a certificate for pub. A nil parent makes it self-signed.
func issue(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// install writes a CA generation made at the given time, certificates first
// in the chain file, and its key if there is one.
func install(t *testing.T, dir string, created time.Time, signer crypto.Signer, certs ...*x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, CertFileName(created)), certificatePEM(certs...), 0o644); err != nil {
		t.Fatal(err)
	}
	if signer != nil {
		data, err := keyset.MarshalPrivateKey(signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, KeyFileName(created)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	touch(t, dir, created, CertFileName(created))
}

// operatorRoot is a self-signed root the operator owns, with the name
// constraints of the profile when constrained.
func operatorRoot(t *testing.T, at time.Time, constrained bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := key(t)
	tmpl := profileTemplate(t, k.Public(), "operator root", at, func(c *x509.Certificate) {
		c.MaxPathLen = -1
		c.MaxPathLenZero = false
		if !constrained {
			c.ExtraExtensions = nil
		}
	})
	return issue(t, tmpl, k.Public(), nil, k), k
}

// signIntermediate signs a signing CA certificate for pub under parent, with
// the profile.
func signIntermediate(t *testing.T, pub crypto.PublicKey, cn string, at time.Time, parent *x509.Certificate, parentKey crypto.Signer, mod func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	return issue(t, profileTemplate(t, pub, cn, at, mod), pub, parent, parentKey)
}

func writeRoots(t *testing.T, path string, at time.Time, certs ...*x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, certificatePEM(certs...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// leaf builds an X.509-SVID the way section 3.4 of the SPEC says, for the
// tests; issuing is the token endpoint's job.
func leaf(t *testing.T, id string, now time.Time, ca CA, mod func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := key(t)
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := SubjectKeyID(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		RawSubject:            mustName(t, td.Name(), id),
		NotBefore:             now.Add(-30 * time.Second),
		NotAfter:              now.Add(time.Hour),
		URIs:                  []*url.URL{u},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          ski,
	}
	if mod != nil {
		mod(tmpl)
	}
	return issue(t, tmpl, k.Public(), ca.Cert, ca.Signer), k
}
