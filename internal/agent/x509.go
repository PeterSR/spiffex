package agent

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	tokenTypeX509SVID = "urn:spiffex:token-type:x509-svid"
	// clockSkew is how far into the future a certificate's notBefore may lie.
	clockSkew = time.Minute
)

// X509SVID is an issued X.509-SVID: the certificate chain, the workload's
// certificate first and the trust domain's anchor left out.
type X509SVID struct {
	Chain    []*x509.Certificate
	SPIFFEID spiffeid.ID
}

// FetchX509SVID requests an X.509-SVID for the public half of key (SPEC
// section 3.4). The private key never leaves the caller.
func (c *IssuerClient) FetchX509SVID(ctx context.Context, cred Credential, key crypto.Signer) (X509SVID, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	now := time.Now()
	form, err := cred.grantParams(c.issuerURL, now)
	if err != nil {
		return X509SVID{}, &CredentialError{err}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return X509SVID{}, fmt.Errorf("making the certificate request: %w", err)
	}
	form["requested_token_type"] = []string{tokenTypeX509SVID}
	form["csr"] = []string{base64.RawURLEncoding.EncodeToString(csr)}

	body, err := c.postToken(ctx, form)
	if err != nil {
		return X509SVID{}, err
	}
	var tr struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		SPIFFEID        string `json:"spiffe_id"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return X509SVID{}, fmt.Errorf("token endpoint: %w", err)
	}
	if tr.IssuedTokenType != tokenTypeX509SVID {
		return X509SVID{}, fmt.Errorf("token endpoint: issued_token_type is %q, want %s", tr.IssuedTokenType, tokenTypeX509SVID)
	}
	der, err := base64.RawURLEncoding.DecodeString(tr.AccessToken)
	if err != nil {
		return X509SVID{}, fmt.Errorf("token endpoint: %w", err)
	}
	chain, err := x509.ParseCertificates(der)
	if err != nil || len(chain) == 0 {
		return X509SVID{}, errors.New("token endpoint: the access token is not a certificate chain")
	}
	// What the workload will present is the certificate, so its contents
	// count; the response fields only have to agree with them.
	leaf := chain[0]
	if len(leaf.URIs) != 1 {
		return X509SVID{}, errors.New("token endpoint: the certificate does not have exactly one URI SAN")
	}
	id, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil || !id.MemberOf(c.trustDomain) || id.String() != tr.SPIFFEID {
		return X509SVID{}, fmt.Errorf("token endpoint: issued %s (response says %q) outside trust domain %s or inconsistent", leaf.URIs[0], tr.SPIFFEID, c.trustDomain)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		return X509SVID{}, errors.New("token endpoint: the certificate is a CA certificate, not a leaf")
	}
	if !sameKey(leaf.PublicKey, key.Public()) {
		return X509SVID{}, errors.New("token endpoint: the certificate is not for the requested key")
	}
	if now.Before(leaf.NotBefore.Add(-clockSkew)) || !leaf.NotAfter.After(now) {
		return X509SVID{}, errors.New("token endpoint: the certificate is not valid now")
	}
	for i := 1; i < len(chain); i++ {
		if err := chain[i-1].CheckSignatureFrom(chain[i]); err != nil {
			return X509SVID{}, fmt.Errorf("token endpoint: the chain is broken at certificate %d: %w", i, err)
		}
	}
	return X509SVID{Chain: chain, SPIFFEID: id}, nil
}

func sameKey(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && e.Equal(b)
}
