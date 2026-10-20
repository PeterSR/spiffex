package issuer

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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/edkey"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// withCA gives the issuer a root of the trust domain, made two days before the
// fixture's clock and valid for validFor from then. mutateDir changes the CA
// directory before it is loaded.
func withCA(t *testing.T, validFor time.Duration, mutateDir func(dir string, made ca.CA)) func(*tokenFixture, *Config) {
	return func(f *tokenFixture, cfg *Config) {
		dir := t.TempDir()
		created := f.now.Add(-48 * time.Hour)
		made, err := ca.Init(dir, td, created, validFor)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{made.File, made.KeyFile} {
			if err := os.Chtimes(filepath.Join(dir, name), created, created); err != nil {
				t.Fatal(err)
			}
		}
		if mutateDir != nil {
			mutateDir(dir, made)
		}
		set, err := ca.Load(ca.Options{Dir: dir, TrustDomain: td, ActivationDelay: DefaultActivationDelay, Retention: ca.Retention(DefaultX509SVIDTTL)}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		cfg.CA = staticCA{set: set, seq: 1000}
	}
}

const longValidity = 365 * 24 * time.Hour

func newX509Fixture(t *testing.T) *tokenFixture {
	return newTokenFixtureWith(t, withCA(t, longValidity, nil))
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// csrDER makes a certificate request signed by key.
func csrDER(t testing.TB, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func enc(der []byte) string { return base64.RawURLEncoding.EncodeToString(der) }

// x509Form is a client credentials request for an X.509-SVID.
func (f *tokenFixture) x509Form(t *testing.T, clientID, csr string) url.Values {
	t.Helper()
	v := f.form(clientID, sign(t, f.ecKey, jose.ES256, f.claims(clientID)))
	v.Set("requested_token_type", TokenTypeX509SVID)
	v.Set("csr", csr)
	return v
}

// x509Chain decodes the access token of an X.509-SVID response.
func x509Chain(t *testing.T, resp response) []*x509.Certificate {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %v", resp.status, resp.body)
	}
	der, err := base64.RawURLEncoding.DecodeString(resp.body["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := x509.ParseCertificates(der)
	if err != nil || len(chain) == 0 {
		t.Fatalf("the access token is not a chain: %v", err)
	}
	return chain
}

func (f *tokenFixture) bundle() *x509bundle.Bundle {
	set, _, _ := f.iss.cfg.CA.Current()
	var anchors []*x509.Certificate
	for _, a := range set.Anchors() {
		anchors = append(anchors, a.Cert)
	}
	return x509bundle.FromX509Authorities(td, anchors)
}

// verifyX509 checks the chain with go-spiffe the way a workload would and
// returns the leaf.
func (f *tokenFixture) verifyX509(t *testing.T, resp response, wantID string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	chain := x509Chain(t, resp)
	id, _, err := x509svid.Verify(chain, f.bundle(), x509svid.WithTime(f.now))
	if err != nil {
		t.Fatalf("go-spiffe refuses the chain: %v", err)
	}
	if id.String() != wantID || resp.body["spiffe_id"] != wantID {
		t.Errorf("SPIFFE ID %s (response %v), want %s", id, resp.body["spiffe_id"], wantID)
	}
	leaf := chain[0]
	if !publicKeyEqual(leaf.PublicKey, key.Public()) {
		t.Error("the leaf is not for the requested key")
	}
	if leaf.Subject.CommonName != wantID || len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != "example.org" {
		t.Errorf("subject %v", leaf.Subject)
	}
	if resp.header.Get("Cache-Control") != "no-store" || resp.body["issued_token_type"] != TokenTypeX509SVID ||
		resp.body["token_type"] != "N_A" || resp.body["expires_in"] != float64(3600) {
		t.Errorf("response %v, headers %v", resp.body, resp.header)
	}
	return leaf
}

func publicKeyEqual(a, b crypto.PublicKey) bool { return sameKey(a, b) }

// With a root the issuer holds, the answer is the leaf alone: the root is the
// anchor and is never sent (an intermediate gets two certificates, below).
func TestX509ChainOfARootCAIsTheLeaf(t *testing.T) {
	f := newX509Fixture(t)
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, newKey(t), nil))))
	if chain := x509Chain(t, resp); len(chain) != 1 {
		t.Fatalf("chain of %d certificates, want the leaf alone", len(chain))
	}
}

// A certificate comes out of every origin kind and both grants, and every
// one of them verifies with go-spiffe.
func TestX509SVIDFromEachOriginKind(t *testing.T) {
	f := newX509Fixture(t)
	rsaKey := newRSAKey(t, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("keys origin, client credentials", func(t *testing.T) {
		for name, key := range map[string]crypto.Signer{"P-256": newKey(t), "P-384": p384, "Ed25519": edKey, "RSA": rsaKey} {
			t.Run(name, func(t *testing.T) {
				resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
				leaf := f.verifyX509(t, resp, "spiffe://example.org/vms/billing", key)
				_, isRSA := key.(*rsa.PrivateKey)
				want := x509.KeyUsageDigitalSignature
				if isRSA {
					want |= x509.KeyUsageKeyEncipherment
				}
				if leaf.KeyUsage != want {
					t.Errorf("key usage %v, want %v", leaf.KeyUsage, want)
				}
			})
		}
	})
	t.Run("jwt origin, token exchange", func(t *testing.T) {
		key := crypto.Signer(edKey)
		token := f.serviceAccountToken(t, "shop", time.Hour, f.iss.URL()+"/origins/kube")
		resp := f.post(t, exchangeForm(token, TokenTypeJWT, func(v url.Values) {
			v.Del("audience")
			v.Set("requested_token_type", TokenTypeX509SVID)
			v.Set("csr", enc(csrDER(t, key, nil)))
		}))
		f.verifyX509(t, resp, "spiffe://example.org/kube/ns/shop", key)
	})
	t.Run("exec origin, token exchange", func(t *testing.T) {
		key := crypto.Signer(p384)
		resp := f.post(t, exchangeForm("i-0abc", TokenTypeExec, func(v url.Values) {
			v.Del("audience")
			v.Set("origin", "aws")
			v.Set("requested_token_type", TokenTypeX509SVID)
			v.Set("csr", enc(csrDER(t, key, nil)))
		}))
		f.verifyX509(t, resp, "spiffe://example.org/aws/i-0abc", key)
	})
	t.Run("origin that lists only x509", func(t *testing.T) {
		key := newKey(t)
		resp := f.post(t, f.x509Form(t, "xonly/xonly", enc(csrDER(t, key, nil))))
		f.verifyX509(t, resp, "spiffe://example.org/xonly/xonly", key)
	})
}

// The expiry follows the issuer's lifetime and the leaf is backdated.
func TestX509SVIDLifetime(t *testing.T) {
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		withCA(t, longValidity, nil)(f, cfg)
		cfg.X509SVIDTTL = 90 * time.Minute
	})
	key := newKey(t)
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
	leaf := x509Chain(t, resp)[0]
	if want := f.now.Add(90 * time.Minute).Truncate(time.Second); !leaf.NotAfter.Equal(want) {
		t.Errorf("notAfter %s, want %s", leaf.NotAfter, want)
	}
	if want := f.now.Add(-30 * time.Second).Truncate(time.Second); !leaf.NotBefore.Equal(want) {
		t.Errorf("notBefore %s, want %s", leaf.NotBefore, want)
	}
	if resp.body["expires_in"] != float64(5400) {
		t.Errorf("expires_in %v", resp.body["expires_in"])
	}
}

// Nothing in a CSR but its key reaches the certificate.
func TestX509IgnoresEveryCSRField(t *testing.T) {
	f := newX509Fixture(t)
	key := newKey(t)
	u, _ := url.Parse("spiffe://example.org/admin")
	oidChallenge := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	rich := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "spiffe://example.org/admin", Organization: []string{"evil"}, OrganizationalUnit: []string{"root"}},
		DNSNames:       []string{"evil.example"},
		EmailAddresses: []string{"root@example.org"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}, // cA true
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x02, 0x04}},       // keyCertSign
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x04, 0x06, 0x02, 0x55, 0x1d}},           // not even a real EKU
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x00}},                      // authority info access
			{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{0x05, 0x00}},                  // unknown and critical
			{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x03, 'e', 'v', 'l'}},                    // subject key identifier
		},
		// The test needs a challengePassword attribute, which only Attributes can carry.
		//lint:ignore SA1019 see above
		Attributes: []pkix.AttributeTypeAndValueSET{{ //nolint:staticcheck // see above
			Type:  oidChallenge,
			Value: [][]pkix.AttributeTypeAndValue{{{Type: oidChallenge, Value: "hunter2"}}},
		}},
	}
	plain := f.verifyX509(t, f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil)))), "spiffe://example.org/vms/billing", key)

	richResp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, rich))))
	got := f.verifyX509(t, richResp, "spiffe://example.org/vms/billing", key)
	if !bytes.Equal(got.RawSubject, plain.RawSubject) {
		t.Errorf("subject %v", got.Subject)
	}
	if len(got.DNSNames)+len(got.EmailAddresses)+len(got.IPAddresses) != 0 || len(got.URIs) != 1 || got.URIs[0].Path != "/vms/billing" {
		t.Errorf("names %v %v %v %v", got.DNSNames, got.EmailAddresses, got.IPAddresses, got.URIs)
	}
	if len(got.Extensions) != len(plain.Extensions) {
		t.Fatalf("%d extensions, want %d", len(got.Extensions), len(plain.Extensions))
	}
	for i, e := range got.Extensions {
		if !e.Id.Equal(plain.Extensions[i].Id) || e.Critical != plain.Extensions[i].Critical || !bytes.Equal(e.Value, plain.Extensions[i].Value) {
			t.Errorf("extension %s differs from the one for a plain request", e.Id)
		}
	}
	if got.IsCA || got.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("isCA %v, key usage %v", got.IsCA, got.KeyUsage)
	}
}

// The CSR cases the issuer refuses, each with invalid_request.
func TestX509BadCSRs(t *testing.T) {
	f := newX509Fixture(t)
	key := newKey(t)
	good := csrDER(t, key, nil)
	tooBig := csrDER(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.Repeat("a", maxCSR)}})
	rsa4104 := newRSAKey(t, 4104)

	// Another exponent in a well-formed request: the key is judged before
	// the signature, which no longer matches.
	rsaGood := csrDER(t, newRSAKey(t, 2048), nil)
	exponent := bytes.Replace(rsaGood, []byte{0x02, 0x03, 0x01, 0x00, 0x01}, []byte{0x02, 0x03, 0x01, 0x00, 0x03}, 1)
	if bytes.Equal(exponent, rsaGood) {
		t.Fatal("no exponent to change")
	}
	// Version 2 instead of 1.
	version := slices.Clone(good)
	i := bytes.Index(version, []byte{0x02, 0x01, 0x00})
	if i < 0 {
		t.Fatal("no version to change")
	}
	version[i+2] = 0x01
	// A signature that does not verify.
	badSignature := slices.Clone(good)
	badSignature[len(badSignature)-1] ^= 0xff

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edBad := csrDER(t, ed, nil)
	edBad[len(edBad)-1] ^= 0xff
	sha384 := csrDER(t, key, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA384})
	pss := csrDER(t, newRSAKey(t, 2048), &x509.CertificateRequest{SignatureAlgorithm: x509.SHA256WithRSAPSS})

	cases := map[string]string{
		"empty":                     "",
		"padding":                   enc(good) + "=",
		"standard alphabet":         strings.NewReplacer("-", "+", "_", "/").Replace(base64.StdEncoding.EncodeToString(append(slices.Clone(good), 0xfb, 0xff))),
		"a line break":              enc(good)[:20] + "\n" + enc(good)[20:],
		"not base64":                "!!!!",
		"not DER":                   enc([]byte("not a request")),
		"truncated":                 enc(good[:len(good)-5]),
		"trailing bytes":            enc(append(slices.Clone(good), 0)),
		"too large":                 enc(tooBig),
		"far too large":             strings.Repeat("A", 100_000),
		"version 2":                 enc(version),
		"bad signature":             enc(badSignature),
		"P-521 key":                 enc(csrDER(t, p521, nil)),
		"P-224 key":                 enc(csrDER(t, p224, nil)),
		"P-384 signed with SHA-512": enc(csrDER(t, p384, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA512})),
		"Ed25519 bad signature":     enc(edBad),
		"RSA 1024":                  enc(csrDER(t, newRSAKey(t, 1024), nil)),
		"RSA 4104":                  enc(csrDER(t, rsa4104, nil)),
		"RSA exponent":              enc(exponent),
		"P-256 signed with SHA-384": enc(sha384),
		"RSASSA-PSS":                enc(pss),
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, f.x509Form(t, "vms/billing", csr))
			if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
				t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
			}
		})
	}

	t.Run("the largest accepted request", func(t *testing.T) {
		// A subject fills the request to just under the cap.
		pad := maxCSR - len(csrDER(t, key, nil)) - 12
		csr := csrDER(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.Repeat("a", pad)}})
		for len(csr) > maxCSR {
			pad -= len(csr) - maxCSR
			csr = csrDER(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.Repeat("a", pad)}})
		}
		if len(csr) < maxCSR-16 {
			t.Fatalf("test request has %d bytes, want just under %d", len(csr), maxCSR)
		}
		if resp := f.post(t, f.x509Form(t, "vms/billing", enc(csr))); resp.status != http.StatusOK {
			t.Errorf("status %d: %v", resp.status, resp.body)
		}
	})
}

// The key of a CSR may not be one the issuer already uses.
func TestX509RefusesKnownKeys(t *testing.T) {
	f := newX509Fixture(t)
	keys, _, _ := f.iss.cfg.Keys.Current()
	cas, _, _ := f.iss.cfg.CA.Current()
	known := map[string]crypto.Signer{
		"a member key":               f.ecKey,
		"another member's key":       f.strangerK,
		"a member's second key, RSA": f.rsaKey,
		"a JWT signing key":          keys.Keys()[0].Signer,
		"a CA key":                   cas.CAs()[0].Signer,
	}
	for name, key := range known {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
			if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
				t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
			}
		})
	}
	if resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, newKey(t), nil)))); resp.status != http.StatusOK {
		t.Errorf("a new key: status %d: %v", resp.status, resp.body)
	}
}

// svid_types decides after authentication, and before the audience
// restriction and the contents of the csr.
func TestX509SVIDTypes(t *testing.T) {
	f := newX509Fixture(t)
	valid := enc(csrDER(t, newKey(t), nil))

	t.Run("an audience restriction leaves JWT-SVIDs only", func(t *testing.T) {
		assertion := sign(t, f.ecKey, jose.ES256, f.claims("narrow/narrow"))
		v := f.form("narrow/narrow", assertion)
		v.Set("requested_token_type", TokenTypeX509SVID)
		v.Set("csr", valid)
		resp := f.post(t, v)
		if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_target" || resp.body["error_description"] != errSVIDTypeNotPermitted.Description {
			t.Fatalf("status %d, body %v; want 400 invalid_target", resp.status, resp.body)
		}
		if again := f.post(t, v); again.status != http.StatusUnauthorized {
			t.Errorf("the refusal did not consume the assertion: status %d", again.status)
		}
	})
	t.Run("a garbage csr does not hide the refusal", func(t *testing.T) {
		resp := f.post(t, f.x509Form(t, "narrow/narrow", "garbage"))
		if resp.body["error"] != "invalid_target" {
			t.Errorf("body %v; want invalid_target before the csr is read", resp.body)
		}
	})
	t.Run("an origin may list x509 under a restriction", func(t *testing.T) {
		key := newKey(t)
		resp := f.post(t, f.x509Form(t, "narrowx/narrowx", enc(csrDER(t, key, nil))))
		f.verifyX509(t, resp, "spiffe://example.org/narrowx/narrowx", key)
	})
	t.Run("an origin without x509, token exchange", func(t *testing.T) {
		token := f.serviceAccountToken(t, "shop", time.Hour, f.iss.URL()+"/origins/kube-jwt")
		resp := f.post(t, exchangeForm(token, TokenTypeJWT, func(v url.Values) {
			v.Del("audience")
			v.Set("requested_token_type", TokenTypeX509SVID)
			v.Set("csr", valid)
		}))
		if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_target" {
			t.Errorf("status %d, body %v; want 400 invalid_target", resp.status, resp.body)
		}
		// The same origin still issues a JWT-SVID.
		token = f.serviceAccountToken(t, "shop", time.Hour, f.iss.URL()+"/origins/kube-jwt")
		if ok := f.post(t, exchangeForm(token, TokenTypeJWT)); ok.status != http.StatusOK {
			t.Errorf("JWT-SVID: status %d: %v", ok.status, ok.body)
		}
	})
}

// Authentication comes first, and whether a csr is present is a property of
// the request that is answered before it.
func TestX509ErrorOrder(t *testing.T) {
	f := newX509Fixture(t)
	valid := enc(csrDER(t, newKey(t), nil))

	t.Run("bad proof with a bad csr is a bad proof", func(t *testing.T) {
		v := f.x509Form(t, "vms/billing", "garbage")
		v.Set("client_assertion", sign(t, f.strangerK, jose.ES256, f.claims("vms/billing")))
		if resp := f.post(t, v); resp.status != http.StatusUnauthorized || resp.body["error"] != "invalid_client" {
			t.Errorf("status %d, body %v; want 401 invalid_client", resp.status, resp.body)
		}
	})
	t.Run("bad proof with a refused origin type is a bad proof", func(t *testing.T) {
		v := f.x509Form(t, "narrow/narrow", valid)
		v.Set("client_assertion", sign(t, f.strangerK, jose.ES256, f.claims("narrow/narrow")))
		if resp := f.post(t, v); resp.status != http.StatusUnauthorized {
			t.Errorf("status %d, body %v; want 401", resp.status, resp.body)
		}
	})
	t.Run("a missing csr is answered before authentication", func(t *testing.T) {
		v := f.x509Form(t, "vms/billing", valid)
		v.Del("csr")
		v.Set("client_assertion", "garbage")
		if resp := f.post(t, v); resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
			t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
		}
	})
	t.Run("a bad csr consumes the assertion", func(t *testing.T) {
		v := f.x509Form(t, "vms/billing", "garbage")
		if resp := f.post(t, v); resp.body["error"] != "invalid_request" {
			t.Fatalf("body %v", resp.body)
		}
		v.Set("csr", valid)
		if resp := f.post(t, v); resp.status != http.StatusUnauthorized {
			t.Errorf("reusing the assertion: status %d, want 401", resp.status)
		}
	})
}

// A csr without the X.509 type, an unknown type, and the parameters that do
// not go with an X.509-SVID.
func TestX509RequestShape(t *testing.T) {
	f := newX509Fixture(t)
	valid := enc(csrDER(t, newKey(t), nil))
	jwtForm := func() url.Values {
		return f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders")
	}
	exchangeX509 := func(mutate ...func(url.Values)) url.Values {
		token := f.serviceAccountToken(t, "shop", time.Hour, f.iss.URL()+"/origins/kube")
		return exchangeForm(token, TokenTypeJWT, append([]func(url.Values){func(v url.Values) {
			v.Del("audience")
			v.Set("requested_token_type", TokenTypeX509SVID)
			v.Set("csr", valid)
		}}, mutate...)...)
	}
	with := func(base url.Values, mutate func(url.Values)) url.Values { mutate(base); return base }

	cases := map[string]url.Values{
		"client credentials, csr with a JWT-SVID request":       with(jwtForm(), func(v url.Values) { v.Set("csr", valid) }),
		"client credentials, csr with the JWT type named":       with(jwtForm(), func(v url.Values) { v.Set("csr", valid); v.Set("requested_token_type", TokenTypeJWT) }),
		"client credentials, empty csr with a JWT-SVID request": with(jwtForm(), func(v url.Values) { v.Set("csr", "") }),
		"client credentials, unknown requested_token_type":      with(jwtForm(), func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token") }),
		"client credentials, the exec type as requested type":   with(jwtForm(), func(v url.Values) { v.Set("requested_token_type", TokenTypeExec) }),
		"client credentials, X.509 with an audience":            with(f.x509Form(t, "vms/billing", valid), func(v url.Values) { v.Set("audience", "orders") }),
		"client credentials, X.509 without a csr":               with(f.x509Form(t, "vms/billing", valid), func(v url.Values) { v.Del("csr") }),
		"client credentials, X.509 with an empty csr":           with(f.x509Form(t, "vms/billing", valid), func(v url.Values) { v.Set("csr", "") }),
		"client credentials, X.509 with two csrs":               with(f.x509Form(t, "vms/billing", valid), func(v url.Values) { v.Add("csr", valid) }),
		"client credentials, requested_token_type twice":        with(f.x509Form(t, "vms/billing", valid), func(v url.Values) { v.Add("requested_token_type", TokenTypeX509SVID) }),
		"token exchange, csr with a JWT-SVID request":           exchangeForm("x", TokenTypeJWT, func(v url.Values) { v.Set("csr", valid) }),
		"token exchange, unknown requested_token_type":          exchangeForm("x", TokenTypeJWT, func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token") }),
		"token exchange, X.509 with an audience":                exchangeX509(func(v url.Values) { v.Set("audience", "orders") }),
		"token exchange, X.509 without a csr":                   exchangeX509(func(v url.Values) { v.Del("csr") }),
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, form)
			if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
				t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
			}
		})
	}
	// The JWT type named outright, with no csr, is still a JWT-SVID.
	v := jwtForm()
	v.Set("requested_token_type", TokenTypeJWT)
	if resp := f.post(t, v); resp.status != http.StatusOK || resp.body["issued_token_type"] != TokenTypeJWT {
		t.Errorf("status %d, body %v", resp.status, resp.body)
	}
}

// Without a CA, with a CA that holds no key, and with one that has expired:
// the right error each time, never a crash, and discovery agrees.
func TestX509WithoutAUsableCA(t *testing.T) {
	discovers := func(f *tokenFixture) bool {
		var doc map[string]any
		resp, err := http.Get(f.iss.URL() + DiscoveryPath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc["spiffex_x509_svid_supported"] == true
	}
	valid := enc(csrDER(t, newKey(t), nil))

	t.Run("no CA", func(t *testing.T) {
		f := newTokenFixture(t)
		resp := f.post(t, f.x509Form(t, "vms/billing", valid))
		if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
			t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
		}
		if discovers(f) {
			t.Error("discovery announces X.509-SVIDs")
		}
		// And a JWT-SVID is untouched.
		if ok := f.post(t, f.form("vms/billing", sign(t, f.ecKey, jose.ES256, f.claims("vms/billing")), "orders")); ok.status != http.StatusOK {
			t.Errorf("JWT-SVID: status %d", ok.status)
		}
	})
	t.Run("a CA whose key was removed", func(t *testing.T) {
		f := newTokenFixtureWith(t, withCA(t, longValidity, func(dir string, made ca.CA) {
			if err := os.Remove(filepath.Join(dir, made.KeyFile)); err != nil {
				t.Fatal(err)
			}
		}))
		resp := f.post(t, f.x509Form(t, "vms/billing", valid))
		if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
			t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
		}
		if discovers(f) {
			t.Error("discovery announces X.509-SVIDs")
		}
	})
	t.Run("a CA that ends in two minutes", func(t *testing.T) {
		f := newTokenFixtureWith(t, withCA(t, 48*time.Hour+2*time.Minute, nil))
		resp := f.post(t, f.x509Form(t, "vms/billing", valid))
		if resp.status != http.StatusInternalServerError || resp.body["error"] != "server_error" {
			t.Errorf("status %d, body %v; want 500 server_error", resp.status, resp.body)
		}
		if discovers(f) {
			t.Error("discovery announces X.509-SVIDs")
		}
	})
	t.Run("an expired CA", func(t *testing.T) {
		f := newTokenFixtureWith(t, withCA(t, longValidity, nil))
		f.now = f.now.Add(2 * longValidity)
		resp := f.post(t, f.x509Form(t, "vms/billing", valid))
		if resp.status != http.StatusInternalServerError || resp.body["error"] != "server_error" {
			t.Errorf("status %d, body %v; want 500 server_error", resp.status, resp.body)
		}
	})
	t.Run("a working CA", func(t *testing.T) {
		f := newX509Fixture(t)
		if !discovers(f) {
			t.Error("discovery does not announce X.509-SVIDs")
		}
	})
}

// A chain that ends before a full lifetime shortens the certificate.
func TestX509ShortenedByTheChain(t *testing.T) {
	f := newTokenFixtureWith(t, withCA(t, 48*time.Hour+30*time.Minute, nil))
	key := newKey(t)
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
	chain := x509Chain(t, resp)
	if _, _, err := x509svid.Verify(chain, f.bundle(), x509svid.WithTime(f.now)); err != nil {
		t.Fatal(err)
	}
	set, _, _ := f.iss.cfg.CA.Current()
	if end := set.CAs()[0].NotAfter(); chain[0].NotAfter.After(end) || end.Sub(chain[0].NotAfter) > time.Second {
		t.Errorf("notAfter %s, want the chain's end %s", chain[0].NotAfter, end)
	}
	if n := resp.body["expires_in"].(float64); n < 29*60 || n > 31*60 {
		t.Errorf("expires_in %v", n)
	}
}

// An intermediate under the operator's root: the response carries the
// intermediate after the leaf and not the root.
func TestX509ChainWithAnIntermediate(t *testing.T) {
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		dir := t.TempDir()
		roots := filepath.Join(t.TempDir(), "roots.pem")
		created := f.now.Add(-48 * time.Hour)
		rootKey := newKey(t)
		nc, err := ca.NameConstraints(td)
		if err != nil {
			t.Fatal(err)
		}
		rootSKI, _ := ca.SubjectKeyID(rootKey.Public())
		rootTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator root"}, NotBefore: created, NotAfter: created.Add(longValidity),
			BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SubjectKeyId: rootSKI, ExtraExtensions: []pkix.Extension{nc},
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		root, _ := x509.ParseCertificate(rootDER)
		interKey := newKey(t)
		interSKI, _ := ca.SubjectKeyID(interKey.Public())
		interTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "spiffex CA", Organization: []string{"example.org"}}, NotBefore: created, NotAfter: created.Add(longValidity / 2),
			BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SubjectKeyId: interSKI, ExtraExtensions: []pkix.Extension{nc},
		}
		interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, interKey.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		pemOf := func(ders ...[]byte) []byte {
			var out []byte
			for _, d := range ders {
				out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
			}
			return out
		}
		keyName := ca.KeyFileName(created)
		keyPEM, err := keyset.MarshalPrivateKey(interKey)
		if err != nil {
			t.Fatal(err)
		}
		certName := ca.CertFileName(created)
		for name, data := range map[string][]byte{keyName: keyPEM, certName: pemOf(interDER)} {
			mode := os.FileMode(0o644)
			if name == keyName {
				mode = 0o600
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(filepath.Join(dir, name), created, created); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(roots, pemOf(rootDER), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(roots, created, created); err != nil {
			t.Fatal(err)
		}
		set, err := ca.Load(ca.Options{Dir: dir, Roots: roots, TrustDomain: td, ActivationDelay: DefaultActivationDelay, Retention: ca.Retention(DefaultX509SVIDTTL)}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		cfg.CA = staticCA{set: set, seq: 1000}
	})
	key := newKey(t)
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
	chain := x509Chain(t, resp)
	if len(chain) != 2 || chain[1].Subject.CommonName != "spiffex CA" {
		t.Fatalf("chain of %d certificates, want the leaf and the intermediate", len(chain))
	}
	if _, _, err := x509svid.Verify(chain, f.bundle(), x509svid.WithTime(f.now)); err != nil {
		t.Fatal(err)
	}
	if chain[0].NotAfter.After(chain[1].NotAfter) {
		t.Error("the leaf outlives the intermediate")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Every certificate is logged with its serial, SPIFFE ID, origin and
// notAfter; an ID too long for a CN is warned about once per origin.
func TestX509LogsEveryCertificate(t *testing.T) {
	var logs syncBuffer
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		withCA(t, longValidity, nil)(f, cfg)
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	key := newKey(t)
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, key, nil))))
	leaf := x509Chain(t, resp)[0]
	out := logs.String()
	for _, want := range []string{"issued X.509-SVID", "serial=" + hex.EncodeToString(leaf.SerialNumber.Bytes()), "spiffe_id=spiffe://example.org/vms/billing", "origin=vms", "not_after="} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "common name") {
		t.Error("warned about a common name for a short ID")
	}
	// An exec proof of 60 characters makes an ID of more than 64.
	for range 2 {
		resp = f.post(t, exchangeForm(strings.Repeat("a", 60), TokenTypeExec, func(v url.Values) {
			v.Del("audience")
			v.Set("origin", "aws")
			v.Set("requested_token_type", TokenTypeX509SVID)
			v.Set("csr", enc(csrDER(t, newKey(t), nil)))
		}))
		leaf = x509Chain(t, resp)[0]
		if leaf.Subject.CommonName != "" || len(leaf.Subject.Organization) != 1 || rawSANCritical(leaf) {
			t.Errorf("subject %v, SAN critical %v; want the organization alone and a SAN that is not critical", leaf.Subject, rawSANCritical(leaf))
		}
	}
	if n := strings.Count(logs.String(), "without a common name"); n != 1 {
		t.Errorf("%d warnings about a missing common name, want 1 per origin", n)
	}
}

func rawSANCritical(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return e.Critical
		}
	}
	return false
}

// The parser is total: whatever it is given, it answers with an error of the
// token endpoint's kind or a key that passed the checks.
func FuzzParseCSR(f *testing.F) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	seed := func(key crypto.Signer, tmpl *x509.CertificateRequest) {
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(enc(der))
	}
	u, _ := url.Parse("spiffe://example.org/x")
	seed(ec, &x509.CertificateRequest{})
	seed(ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x", Organization: []string{"y"}}, URIs: []*url.URL{u}, DNSNames: []string{"a.example"}})
	seed(rk, &x509.CertificateRequest{})
	seed(rk, &x509.CertificateRequest{SignatureAlgorithm: x509.SHA512WithRSA})
	seed(rk, &x509.CertificateRequest{SignatureAlgorithm: x509.SHA256WithRSAPSS})
	seed(p384, &x509.CertificateRequest{})
	seed(p384, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256})
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	seed(edKey, &x509.CertificateRequest{})
	seed(edKey, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: []*url.URL{u}})
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	seed(p521, &x509.CertificateRequest{})
	for _, key := range smallOrderEncodings(f) {
		f.Add(enc(smallOrderCSR(f, key)))
	}
	for _, s := range []string{"", "AA", "MAA", "MIIB", "!!", strings.Repeat("A", 20_000), "MIGAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pub, err := parseCSR(raw)
		if err != nil {
			if _, ok := err.(*oauthError); !ok {
				t.Fatalf("error of type %T: %v", err, err)
			}
			return
		}
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
				t.Fatalf("accepted a key on %s", k.Curve.Params().Name)
			}
		case ed25519.PublicKey:
			if err := edkey.Check(k); err != nil {
				t.Fatalf("accepted an Ed25519 key that is not acceptable: %v", err)
			}
		case *rsa.PublicKey:
			if bits := k.N.BitLen(); bits < 2048 || bits > 4096 || k.E != 65537 {
				t.Fatalf("accepted an RSA key of %d bits, exponent %d", bits, k.E)
			}
		default:
			t.Fatalf("accepted a key of type %T", pub)
		}
		if len(raw) > base64.RawURLEncoding.EncodedLen(maxCSR) {
			t.Fatal("accepted an oversized request")
		}
	})
}

// The key is judged before the signature: a request with an unacceptable key
// and a signature that cannot verify is refused for its key.
func TestCSRKeyIsJudgedBeforeTheSignature(t *testing.T) {
	rsaGood := csrDER(t, newRSAKey(t, 2048), nil)
	exponent := bytes.Replace(rsaGood, []byte{0x02, 0x03, 0x01, 0x00, 0x01}, []byte{0x02, 0x03, 0x01, 0x00, 0x03}, 1)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	badSignature := csrDER(t, p521, nil)
	badSignature[len(badSignature)-1] ^= 0xff
	for name, der := range map[string][]byte{"exponent": exponent, "curve": badSignature} {
		_, err := parseCSR(enc(der))
		if err == nil || !strings.Contains(err.Error(), "csr key must be") {
			t.Errorf("%s: %v, want the key refused", name, err)
		}
	}
}

// Requests made by OpenSSL, the tool most operators will use, are accepted,
// whatever names they ask for.
func TestOpenSSLRequestsAreAccepted(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	dir := t.TempDir()
	cases := map[string][]string{
		"P-256, empty subject": {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-subj", "/"},
		"P-256, names":         {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-subj", "/CN=root", "-addext", "subjectAltName=DNS:evil.example,IP:10.0.0.1"},
		"P-384":                {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-subj", "/"},
		"P-384, SHA-384":       {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-sha384", "-subj", "/"},
		"Ed25519":              {"-newkey", "ed25519", "-subj", "/CN=x"},
		"RSA 3072":             {"-newkey", "rsa:3072", "-subj", "/O=x"},
		"RSA 2048, SHA-512":    {"-newkey", "rsa:2048", "-sha512", "-subj", "/"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, "r.csr")
			full := append([]string{"req", "-new", "-nodes", "-keyout", filepath.Join(dir, "r.key"), "-outform", "DER", "-out", out}, args...)
			if b, err := exec.Command(openssl, full...).CombinedOutput(); err != nil {
				t.Skipf("openssl cannot make this request: %v\n%s", err, b)
			}
			der, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseCSR(enc(der)); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// Keys of every accepted type compare, and never across types.
func TestSameKey(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256 := newKey(t)
	for name, tc := range map[string]struct {
		a, b crypto.PublicKey
		want bool
	}{
		"Ed25519 equal":       {pubA, append(ed25519.PublicKey(nil), pubA...), true},
		"Ed25519 different":   {pubA, pubB, false},
		"P-384 equal":         {&p384.PublicKey, &p384.PublicKey, true},
		"P-384 against P-256": {&p384.PublicKey, &p256.PublicKey, false},
		"Ed25519 against EC":  {pubA, &p256.PublicKey, false},
	} {
		if got := sameKey(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// fixedSigner signs with a constant, for keys nobody holds a private key of.
type fixedSigner struct {
	pub ed25519.PublicKey
	sig []byte
}

func (s fixedSigner) Public() crypto.PublicKey { return s.pub }
func (s fixedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return s.sig, nil
}

// smallOrderEncodings are Ed25519 public keys that are small-order points or
// not canonical encodings: the eight points of order dividing 8 and the
// non-canonical forms libsodium blocks.
func smallOrderEncodings(t testing.TB) map[string][]byte {
	t.Helper()
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	signed := func(b []byte) []byte {
		c := slices.Clone(b)
		c[31] |= 0x80
		return c
	}
	le := func(n *big.Int) []byte {
		b := n.FillBytes(make([]byte, 32))
		slices.Reverse(b)
		return b
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	identity, zero := le(big.NewInt(1)), le(big.NewInt(0))
	minusOne := le(new(big.Int).Sub(p, big.NewInt(1)))
	order8a := unhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	order8b := unhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	return map[string][]byte{
		"identity":                identity,
		"order 2":                 minusOne,
		"order 4":                 zero,
		"order 4, other sign":     signed(zero),
		"order 8 a":               order8a,
		"order 8 a, other sign":   signed(order8a),
		"order 8 b":               order8b,
		"order 8 b, other sign":   signed(order8b),
		"identity, x=0 with sign": signed(identity),
		"y=p":                     le(p),
		"y=p+1":                   le(new(big.Int).Add(p, big.NewInt(1))),
		"y=p+1 with sign":         signed(le(new(big.Int).Add(p, big.NewInt(1)))),
	}
}

// universalSignature is R = identity, S = 0: it verifies for every message
// under the identity key.
func universalSignature() []byte {
	sig := make([]byte, 64)
	sig[0] = 1
	return sig
}

// smallOrderCSR is a request for the key, with the universal signature. Go
// will not sign for keys other than the identity whose signature fails to
// verify, so it starts from the identity's request and swaps the key in; the
// key is judged before the signature either way.
func smallOrderCSR(t testing.TB, key []byte) []byte {
	t.Helper()
	identity := make([]byte, 32)
	identity[0] = 1
	der := csrDER(t, fixedSigner{ed25519.PublicKey(identity), universalSignature()}, nil)
	return bytes.Replace(der, identity, key, 1)
}

// An Ed25519 key of small order passes any proof of possession, so it is
// refused: the certificate would be public property for its whole lifetime.
func TestX509RefusesSmallOrderEd25519Keys(t *testing.T) {
	f := newX509Fixture(t)
	identity := smallOrderEncodings(t)["identity"]
	// The premise: Go accepts the signature, for any message.
	if !ed25519.Verify(ed25519.PublicKey(identity), []byte("any message"), universalSignature()) {
		t.Fatal("the identity key no longer verifies the universal signature; the premise of the test is gone")
	}
	for name, key := range smallOrderEncodings(t) {
		t.Run(name, func(t *testing.T) {
			resp := f.post(t, f.x509Form(t, "vms/billing", enc(smallOrderCSR(t, key))))
			if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
				t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
			}
		})
	}
}

// The impersonation the check prevents: with the identity key the issuer would
// have certified a key anyone can sign for.
func TestX509NoCertificateForAKeyNobodyHolds(t *testing.T) {
	f := newX509Fixture(t)
	before := f.post(t, f.x509Form(t, "vms/billing", enc(smallOrderCSR(t, smallOrderEncodings(t)["identity"]))))
	if before.status == http.StatusOK {
		t.Fatalf("a certificate was issued for the identity key: %v", before.body)
	}
	if _, ok := before.body["access_token"]; ok {
		t.Error("the refusal carries a token")
	}
}

// A request is refused with invalid_request, not a server error, when a
// reload during authentication leaves the issuer without a CA.
func TestX509CALostDuringAuthentication(t *testing.T) {
	var flip *flippingCA
	f := newTokenFixtureWith(t, func(f *tokenFixture, cfg *Config) {
		withCA(t, longValidity, nil)(f, cfg)
		working := cfg.CA.(staticCA)
		flip = &flippingCA{first: working, then: staticCA{set: emptyCASet(t, f.now), seq: 1001}}
		cfg.CA = flip
	})
	resp := f.post(t, f.x509Form(t, "vms/billing", enc(csrDER(t, newKey(t), nil))))
	if resp.status != http.StatusBadRequest || resp.body["error"] != "invalid_request" {
		t.Errorf("status %d, body %v; want 400 invalid_request", resp.status, resp.body)
	}
	if flip.reads.Load() < 2 {
		t.Errorf("the source was read %d times; the test did not reach the second read", flip.reads.Load())
	}
}

// flippingCA serves a working set to its first reader and an empty one after.
type flippingCA struct {
	first, then staticCA
	reads       atomic.Int32
}

func (c *flippingCA) Current() (*ca.Set, uint64, <-chan struct{}) {
	if c.reads.Add(1) == 1 {
		return c.first.Current()
	}
	return c.then.Current()
}

// emptyCASet is a set with an anchor and no CA that can sign: a root whose
// key was removed.
func emptyCASet(t *testing.T, now time.Time) *ca.Set {
	t.Helper()
	dir := t.TempDir()
	created := now.Add(-48 * time.Hour)
	made, err := ca.Init(dir, td, created, longValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, made.KeyFile)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{made.File} {
		if err := os.Chtimes(filepath.Join(dir, name), created, created); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ca.Load(ca.Options{Dir: dir, TrustDomain: td, ActivationDelay: DefaultActivationDelay, Retention: ca.Retention(DefaultX509SVIDTTL)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.CAs()) != 0 {
		t.Fatal("the set has a CA")
	}
	return set
}
