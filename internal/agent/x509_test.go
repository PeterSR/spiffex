package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// selfSignedLeaf is a certificate for key naming id, which is all the client
// checks of a chain of one.
func selfSignedLeaf(t *testing.T, key *ecdsa.PrivateKey, id string, notAfter time.Time, isCA bool) []byte {
	t.Helper()
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u},
		BasicConstraintsValid: true, IsCA: isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The client sends a CSR with the requested type and refuses certificates
// that are not what it asked for.
func TestFetchX509SVID(t *testing.T) {
	mine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := "spiffe://example.org/billing"
	cases := map[string]struct {
		key       *ecdsa.PrivateKey
		id        string
		notAfter  time.Time
		issued    string
		reportID  string
		isCA      bool
		wantError bool
	}{
		"accepted":               {mine, good, time.Now().Add(time.Hour), tokenTypeX509SVID, good, false, false},
		"another key":            {other, good, time.Now().Add(time.Hour), tokenTypeX509SVID, good, false, true},
		"another trust domain":   {mine, "spiffe://other.org/billing", time.Now().Add(time.Hour), tokenTypeX509SVID, "spiffe://other.org/billing", false, true},
		"the response disagrees": {mine, good, time.Now().Add(time.Hour), tokenTypeX509SVID, "spiffe://example.org/other", false, true},
		"expired":                {mine, good, time.Now().Add(-time.Second), tokenTypeX509SVID, good, false, true},
		"a CA certificate":       {mine, good, time.Now().Add(time.Hour), tokenTypeX509SVID, good, true, true},
		"a JWT-SVID type":        {mine, good, time.Now().Add(time.Hour), tokenTypeJWT, good, false, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := fakeIssuer(t, func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.PostForm.Get("requested_token_type") != tokenTypeX509SVID || r.PostForm.Has("audience") {
					t.Errorf("form %v", r.PostForm)
				}
				der, err := base64.RawURLEncoding.DecodeString(r.PostForm.Get("csr"))
				if err != nil {
					t.Fatal(err)
				}
				csr, err := x509.ParseCertificateRequest(der)
				if err != nil || csr.CheckSignature() != nil {
					t.Errorf("csr: %v", err)
				}
				if csr.Subject.String() != "" || len(csr.URIs)+len(csr.DNSNames) != 0 {
					t.Errorf("the csr asks for names: %v", csr.Subject)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":      base64.RawURLEncoding.EncodeToString(selfSignedLeaf(t, c.key, c.id, c.notAfter, c.isCA)),
					"issued_token_type": c.issued, "token_type": "N_A", "expires_in": 3600, "spiffe_id": c.reportID,
				})
			})
			client, err := Discover(context.Background(), srv.URL, spiffeid.TrustDomain{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			svid, err := client.FetchX509SVID(context.Background(), testCredential(t), mine)
			if (err != nil) != c.wantError {
				t.Fatalf("error %v, want error %v", err, c.wantError)
			}
			if err == nil && svid.SPIFFEID.String() != good {
				t.Errorf("SPIFFE ID %s", svid.SPIFFEID)
			}
		})
	}
}
