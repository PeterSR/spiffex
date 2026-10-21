package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// LeafBackdate is how far before the current time an X.509-SVID's notBefore
// lies, to absorb clock differences (SPEC section 3.4).
const LeafBackdate = 30 * time.Second

// IssueLeaf signs the X.509-SVID of SPEC section 3.4 for id and the
// requester's public key with the CA of choice, valid until choice.NotAfter.
// Nothing but the key comes from the requester.
func IssueLeaf(choice Choice, id spiffeid.ID, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	// Names too long for RFC 5280's bounds are left out, never shortened.
	var cn string
	if len(id.String()) <= MaxNameLength {
		cn = id.String()
	}
	return IssueLeafCN(choice, id, cn, pub, now)
}

// IssueLeafCN is IssueLeaf with the common name chosen by the caller: cn is
// the whole name, or empty for none. The caller has checked that it is at most
// MaxNameLength characters; it is refused here otherwise rather than cut.
func IssueLeafCN(choice Choice, id spiffeid.ID, cn string, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	if len(cn) > MaxNameLength {
		return nil, fmt.Errorf("the common name is %d characters, more than the %d allowed", len(cn), MaxNameLength)
	}
	var org string
	if name := id.TrustDomain().Name(); len(name) <= MaxNameLength {
		org = name
	}
	subject, err := Name(org, cn)
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		return nil, err
	}
	serial, err := SerialNumber()
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	usage := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}
	// A CA that has only just become valid would otherwise be older than its
	// own certificate.
	notBefore := now.Add(-LeafBackdate).Truncate(time.Second)
	if start := choice.CA.notBefore(); start.After(notBefore) {
		notBefore = start
	}
	// Go marks the SAN critical exactly when the subject is empty.
	template := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            subject,
		NotBefore:             notBefore,
		NotAfter:              choice.NotAfter,
		URIs:                  []*url.URL{uri},
		BasicConstraintsValid: true,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, choice.CA.Cert, pub, choice.CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("signing the X.509-SVID: %w", err)
	}
	return x509.ParseCertificate(der)
}
