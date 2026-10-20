package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestInitMakesAProfileCertificate(t *testing.T) {
	dir := t.TempDir()
	c := initRoot(t, dir, t0)
	cert := c.Cert

	if cert.Version != 3 || !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("basic constraints: version %d, CA %v, path length %d", cert.Version, cert.IsCA, cert.MaxPathLen)
	}
	for oid, want := range map[string]bool{"2.5.29.19": true, "2.5.29.15": true, "2.5.29.30": true} {
		var found bool
		for _, e := range cert.Extensions {
			if e.Id.String() == oid {
				found = true
				if e.Critical != want {
					t.Errorf("extension %s critical = %v, want %v", oid, e.Critical, want)
				}
			}
		}
		if !found {
			t.Errorf("extension %s is missing", oid)
		}
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %v", cert.KeyUsage)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm = %v", cert.SignatureAlgorithm)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("public key = %T", cert.PublicKey)
	}
	if point, err := cert.PublicKey.(*ecdsa.PublicKey).Bytes(); err != nil {
		t.Fatal(err)
	} else if want := sha1.Sum(point); !bytes.Equal(cert.SubjectKeyId, want[:]) {
		t.Errorf("subject key identifier is not the SHA-1 of the key bit string")
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 127 {
		t.Errorf("serial number %v is not a positive 127-bit integer", cert.SerialNumber)
	}
	if len(cert.URIs)+len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses) != 0 {
		t.Errorf("names: %v %v %v %v", cert.URIs, cert.DNSNames, cert.IPAddresses, cert.EmailAddresses)
	}
	if !cert.NotBefore.Before(t0) || cert.NotAfter.Sub(t0) < 4*365*24*time.Hour {
		t.Errorf("validity %s to %s", cert.NotBefore, cert.NotAfter)
	}
	if err := checkProfile(cert, td); err != nil {
		t.Errorf("profile: %v", err)
	}
	if !isSelfSigned(cert) {
		t.Error("the root is not self-signed")
	}

	// Subject: the trust domain and a common name, both UTF8String, each in
	// a set of its own.
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawSubject, &rdns); err != nil || len(rest) > 0 || len(rdns) != 2 {
		t.Fatalf("subject: %v %d RDNs", err, len(rdns))
	}
	for i, rdn := range rdns {
		if len(rdn) != 1 {
			t.Fatalf("RDN %d has %d attributes", i, len(rdn))
		}
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(cert.RawSubject, &raw); err != nil {
		t.Fatal(err)
	}
	for body := raw.Bytes; len(body) > 0; {
		var set asn1.RawValue
		var err error
		if body, err = asn1.Unmarshal(body, &set); err != nil {
			t.Fatal(err)
		}
		var attr asn1.RawValue
		if _, err := asn1.Unmarshal(set.Bytes, &attr); err != nil {
			t.Fatal(err)
		}
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil {
			t.Fatal(err)
		}
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &value); err != nil {
			t.Fatal(err)
		}
		if value.Tag != asn1.TagUTF8String {
			t.Errorf("attribute %s has ASN.1 tag %d, want UTF8String", oid, value.Tag)
		}
	}
	if cert.Subject.CommonName == "" || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "example.org" {
		t.Errorf("subject = %v", cert.Subject)
	}

	for _, f := range []struct {
		name string
		mode os.FileMode
	}{{c.KeyFile, 0o600}, {c.File, 0o644}} {
		info, err := os.Stat(filepath.Join(dir, f.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != f.mode {
			t.Errorf("%s mode = %o, want %o", f.name, info.Mode().Perm(), f.mode)
		}
	}

	if _, err := Init(t.TempDir(), td, t0, time.Hour); err == nil {
		t.Error("a root valid for an hour was made")
	}
	again, err := Init(t.TempDir(), td, t0, MinRootLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again.Cert.RawSubject, cert.RawSubject) {
		t.Error("two generations made in the same second share a subject")
	}
	if _, err := Init(dir, td, t0, MinRootLifetime); err == nil {
		t.Error("a second root in the same second was written over the first")
	}
}

func TestLongTrustDomainLeavesOutTheOrganization(t *testing.T) {
	long := strings.Repeat("a", 60) + ".example.org"
	name, err := Name(long[:MaxNameLength+1], "cn")
	if err != nil {
		t.Fatal(err)
	}
	if len(name) == 0 {
		t.Fatal("no name")
	}
	if name, _ = Name("", ""); !bytes.Equal(name, emptyName) {
		t.Errorf("a name without attributes = %x, want an empty sequence", name)
	}
}

// The name constraints keep a stolen CA key to this trust domain, in Go's
// verifier and in go-spiffe's.
func TestNameConstraintsRefuseOtherNames(t *testing.T) {
	dir := t.TempDir()
	// go-spiffe verifies at the current time.
	now := time.Now()
	c := initRoot(t, dir, now.Add(-time.Hour))
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{c.Cert})

	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	goVerify := func(l *x509.Certificate) error {
		_, err := l.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}

	good, _ := leaf(t, "spiffe://example.org/ns/shop/sa/billing", now, c, nil)
	if err := goVerify(good); err != nil {
		t.Fatalf("Go refuses a leaf of the trust domain: %v", err)
	}
	if id, _, err := x509svid.ParseAndVerify([][]byte{good.Raw}, bundle); err != nil || id.String() != "spiffe://example.org/ns/shop/sa/billing" {
		t.Fatalf("go-spiffe: %v %v", id, err)
	}
	if empty, _ := leaf(t, "spiffe://example.org/x", now, c, func(l *x509.Certificate) { l.RawSubject = emptyName }); goVerify(empty) != nil {
		t.Error("a leaf with an empty subject is refused")
	}

	forged := []struct {
		name string
		mod  func(*x509.Certificate)
		id   string
	}{
		{"another trust domain", nil, "spiffe://other.org/ns/shop/sa/billing"},
		{"a subdomain, another trust domain", nil, "spiffe://sub.example.org/ns/shop/sa/billing"},
		{"a longer name that ends the same", nil, "spiffe://notexample.org/x"},
		{"a DNS name beside the ID", func(l *x509.Certificate) { l.DNSNames = []string{"example.org"} }, "spiffe://example.org/x"},
		{"an IP address beside the ID", func(l *x509.Certificate) { l.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")} }, "spiffe://example.org/x"},
		{"a mailbox beside the ID", func(l *x509.Certificate) { l.EmailAddresses = []string{"a@example.org"} }, "spiffe://example.org/x"},
		{"another ID beside the ID", func(l *x509.Certificate) {
			l.URIs = append(l.URIs, &url.URL{Scheme: "spiffe", Host: "other.org", Path: "/x"})
		}, "spiffe://example.org/x"},
	}
	for _, f := range forged {
		l, _ := leaf(t, f.id, now, c, f.mod)
		if err := goVerify(l); err == nil {
			t.Errorf("%s: Go accepted the leaf", f.name)
		}
		if _, _, err := x509svid.ParseAndVerify([][]byte{l.Raw}, bundle); err == nil {
			t.Errorf("%s: go-spiffe accepted the leaf", f.name)
		}
	}

	// A subject that names something else is not constrained by the CA
	// (the SAN is the identity), but the SAN still is.
	other, _ := leaf(t, "spiffe://example.org/x", now, c, func(l *x509.Certificate) {
		l.RawSubject = mustName(t, "Somebody Else", "evil")
	})
	if err := goVerify(other); err != nil {
		t.Errorf("a leaf whose subject differs is refused: %v", err)
	}
}

func TestProfileRefusals(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ncNo := func(c *x509.Certificate) { c.ExtraExtensions = nil }
	plainNC := func(permitted, excluded []generalName, critical bool) func(*x509.Certificate) {
		return func(c *x509.Certificate) {
			der, err := marshalNameConstraints(permitted, excluded)
			if err != nil {
				t.Fatal(err)
			}
			c.ExtraExtensions = []pkix.Extension{{Id: oidNameConstraints, Critical: critical, Value: der}}
		}
	}
	permitted, excluded := wantedConstraints(td)
	cases := []struct {
		name string
		key  crypto.Signer
		mod  func(*x509.Certificate)
		want string
	}{
		{"no name constraints", nil, ncNo, "no nameConstraints"},
		{"name constraints not critical", nil, plainNC(permitted, excluded, false), "not marked critical"},
		{"no permitted subtree", nil, plainNC(nil, excluded, true), "not exactly"},
		{"a permitted DNS subtree too", nil, plainNC(append(permitted[:1:1], generalName{tagDNS, "example.org"}), excluded, true), "not exactly"},
		{"the wrong trust domain", nil, plainNC([]generalName{{tagURI, "other.org"}}, excluded, true), "not exactly"},
		{"no excluded subdomains", nil, plainNC(permitted, excluded[1:], true), "not exactly"},
		{"a directoryName constraint", nil, plainNC(permitted, append(excluded[:5:5], generalName{4, "\x30\x00"}), true), "not exactly"},
		{"no IP exclusions", nil, plainNC(permitted, excluded[:2], true), "not exactly"},
		{"no path length", nil, func(c *x509.Certificate) { c.MaxPathLen = -1; c.MaxPathLenZero = false }, "pathLenConstraint 0"},
		{"a path length of one", nil, func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }, "pathLenConstraint 0"},
		{"not a CA", nil, func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false }, "basicConstraints"},
		{"digitalSignature as well", nil, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageDigitalSignature }, "keyUsage"},
		{"no cRLSign", nil, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign }, "keyUsage"},
		{"an empty subject", nil, func(c *x509.Certificate) { c.RawSubject = emptyName }, "empty subject"},
		{"a DNS name", nil, func(c *x509.Certificate) { c.DNSNames = []string{"example.org"} }, "subjectAltName"},
		{"another trust domain's URI", nil, func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "spiffe", Host: "other.org"}} }, "subjectAltName"},
		{"a URI with a path", nil, func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/ca"}} }, "subjectAltName"},
		{"an RSA key of 1024 bits", rsa1024, nil, "1024 bits"},
		{"a P-521 key", p521, nil, "P-521"},
		{"RSA-PSS", rsa2048, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA256WithRSAPSS }, "RSASSA-PSS"},
		{"a serverAuth-only extended key usage", nil, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, "extendedKeyUsage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			var k crypto.Signer = key(t)
			if c.key != nil {
				k = c.key
			}
			cert := issue(t, profileTemplate(t, k.Public(), "test "+c.name, t0, c.mod), k.Public(), nil, k)
			install(t, dir, t0, k, cert)
			_, err := Load(testOptions(dir), t0.Add(time.Hour))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}

	t.Run("accepted variants", func(t *testing.T) {
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]struct {
			key crypto.Signer
			mod func(*x509.Certificate)
		}{
			"P-384":               {p384, nil},
			"RSA 3072":            {rsa3072, nil},
			"the trust domain ID": {nil, func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.org"}} }},
			"serverAuth and clientAuth": {nil, func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			}},
		} {
			dir := t.TempDir()
			var k crypto.Signer = key(t)
			if c.key != nil {
				k = c.key
			}
			cert := issue(t, profileTemplate(t, k.Public(), "test "+name, t0, c.mod), k.Public(), nil, k)
			install(t, dir, t0, k, cert)
			if _, err := Load(testOptions(dir), t0.Add(time.Hour)); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// Go makes a subject key identifier for any CA it signs, so a certificate
// without one is made by taking it off a parsed one.
func TestProfileNeedsASubjectKeyIdentifier(t *testing.T) {
	c := initRoot(t, t.TempDir(), t0)
	cert := *c.Cert
	cert.SubjectKeyId = nil
	if err := checkProfile(&cert, td); err == nil || !strings.Contains(err.Error(), "subjectKeyIdentifier") {
		t.Errorf("err = %v", err)
	}
}

// The extension is the same bytes whoever builds it, and the strict parser
// reads it back.
func TestNameConstraintsRoundTrip(t *testing.T) {
	ext, err := NameConstraints(td)
	if err != nil {
		t.Fatal(err)
	}
	if !ext.Critical {
		t.Error("not critical")
	}
	permitted, excluded, err := parseNameConstraints(ext.Value)
	if err != nil {
		t.Fatal(err)
	}
	wantP, wantE := wantedConstraints(td)
	if !sameNames(permitted, wantP) || !sameNames(excluded, wantE) {
		t.Errorf("read back %v %v", permitted, excluded)
	}
	// A minimum other than zero is refused.
	bad, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseNameConstraints(append(bad, 0)); err == nil {
		t.Error("trailing data accepted")
	}
}

// The parsers read bytes anyone with write access to ca_dir or ca_roots can
// choose; none may panic. A few seconds of `go test -fuzz` at a time is
// enough to keep them honest.
func FuzzParseNameConstraints(f *testing.F) {
	ext, err := NameConstraints(td)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ext.Value)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0xa0, 0x01, 0x00})
	f.Add([]byte("not DER"))
	f.Fuzz(func(t *testing.T, data []byte) {
		permitted, excluded, err := parseNameConstraints(data)
		if err == nil {
			// Whatever is read can be written and read back the same.
			again, err := marshalNameConstraints(permitted, excluded)
			if err != nil {
				return
			}
			p2, e2, err := parseNameConstraints(again)
			if err != nil || !sameNames(permitted, p2) || !sameNames(excluded, e2) {
				t.Fatalf("round trip of %x changed it: %v", data, err)
			}
		}
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidNameConstraints, Critical: true, Value: data}}}
		_ = checkNameConstraints(cert, td)
		_ = fencesTrustDomain(cert, td)
	})
}

func FuzzCheckSubjectAltName(f *testing.F) {
	uri, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: []byte{0x86, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uri)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x02, 0x82, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSubjectAltName, Value: data}}}
		_ = checkSubjectAltName(cert, td)
	})
}
