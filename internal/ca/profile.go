package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// GeneralName tags of RFC 5280, the ones name constraints and the CA's
// subject alternative name deal with.
const (
	tagEmail = 1
	tagDNS   = 2
	tagURI   = 6
	tagIP    = 7
)

// generalName is a name form and the bytes of its value.
type generalName struct {
	tag   int
	value string
}

// NameConstraints returns the critical nameConstraints extension every
// signing CA carries (SPEC section 2.5): only SPIFFE IDs of the trust
// domain, no DNS name, IP address or mailbox, and no subdomain of the trust
// domain, which is another trust domain. There are no directoryName subtrees,
// for the reasons the specification gives.
func NameConstraints(td spiffeid.TrustDomain) (pkix.Extension, error) {
	permitted, excluded := wantedConstraints(td)
	der, err := marshalNameConstraints(permitted, excluded)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidNameConstraints, Critical: true, Value: der}, nil
}

func wantedConstraints(td spiffeid.TrustDomain) (permitted, excluded []generalName) {
	permitted = []generalName{{tagURI, td.Name()}}
	excluded = []generalName{
		{tagURI, "." + td.Name()},
		{tagDNS, ""},
		{tagIP, string(make([]byte, 8))},
		{tagIP, string(make([]byte, 32))},
		{tagEmail, ""},
	}
	return permitted, excluded
}

func marshalNameConstraints(permitted, excluded []generalName) ([]byte, error) {
	subtrees := func(names []generalName) ([]byte, error) {
		var out []byte
		for _, n := range names {
			base := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: n.tag, Bytes: []byte(n.value)}
			der, err := asn1.Marshal(struct{ Base asn1.RawValue }{base})
			if err != nil {
				return nil, err
			}
			out = append(out, der...)
		}
		return out, nil
	}
	var body []byte
	for i, names := range [][]generalName{permitted, excluded} {
		if len(names) == 0 {
			continue
		}
		inner, err := subtrees(names)
		if err != nil {
			return nil, err
		}
		der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: i, IsCompound: true, Bytes: inner})
		if err != nil {
			return nil, err
		}
		body = append(body, der...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// parseNameConstraints reads a nameConstraints extension value strictly: the
// subtrees must have no minimum and no maximum, as RFC 5280 requires.
func parseNameConstraints(der []byte) (permitted, excluded []generalName, err error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) > 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, nil, errors.New("not a name constraints sequence")
	}
	next := 0
	for body := seq.Bytes; len(body) > 0; {
		var part asn1.RawValue
		var err error
		if body, err = asn1.Unmarshal(body, &part); err != nil {
			return nil, nil, err
		}
		if part.Class != asn1.ClassContextSpecific || !part.IsCompound || part.Tag < next || part.Tag > 1 {
			return nil, nil, errors.New("subtrees out of order or of an unknown kind")
		}
		next = part.Tag + 1
		var names []generalName
		for inner := part.Bytes; len(inner) > 0; {
			var subtree asn1.RawValue
			if inner, err = asn1.Unmarshal(inner, &subtree); err != nil {
				return nil, nil, err
			}
			var base asn1.RawValue
			rest, err := asn1.Unmarshal(subtree.Bytes, &base)
			if err != nil || len(rest) > 0 || base.Class != asn1.ClassContextSpecific || base.IsCompound {
				return nil, nil, errors.New("a subtree that is not a single plain name")
			}
			names = append(names, generalName{base.Tag, string(base.Bytes)})
		}
		if part.Tag == 0 {
			permitted = names
		} else {
			excluded = names
		}
	}
	return permitted, excluded, nil
}

func sameNames(a, b []generalName) bool {
	cmp := func(x, y generalName) int {
		if x.tag != y.tag {
			return x.tag - y.tag
		}
		return strings.Compare(x.value, y.value)
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, cmp)
	slices.SortFunc(b, cmp)
	return slices.Equal(a, b)
}

func extension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func checkNameConstraints(cert *x509.Certificate, td spiffeid.TrustDomain) error {
	ext, ok := extension(cert, oidNameConstraints)
	if !ok {
		return errors.New("has no nameConstraints extension")
	}
	if !ext.Critical {
		return errors.New("its nameConstraints is not marked critical")
	}
	permitted, excluded, err := parseNameConstraints(ext.Value)
	if err != nil {
		return fmt.Errorf("its nameConstraints: %w", err)
	}
	wantPermitted, wantExcluded := wantedConstraints(td)
	if !sameNames(permitted, wantPermitted) || !sameNames(excluded, wantExcluded) {
		return fmt.Errorf("its nameConstraints are not exactly the ones SPEC section 2.5 requires for %s: permit only the URI %s, exclude the URI .%s, every DNS name, IP address and mailbox, and have no directoryName", td, td, td)
	}
	return nil
}

// fencesTrustDomain reports whether a root carries the name constraints of
// SPEC section 2.5 in full, exactly as a signing CA does. Anything less is not
// a fence: a CA under the root could still certify DNS names, addresses or
// mailboxes, which every verifier that pinned the bundle would accept.
func fencesTrustDomain(cert *x509.Certificate, td spiffeid.TrustDomain) bool {
	return checkNameConstraints(cert, td) == nil
}

// keySignatureAlgorithm returns the signature algorithm a CA with this public
// key signs with, and an error for a key a CA may not have.
func keySignatureAlgorithm(pub crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSAWithSHA384, nil
		}
		return 0, fmt.Errorf("has an unsupported EC curve %s, want P-256 or P-384", pub.Curve.Params().Name)
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < 2048 || bits > 4096 {
			return 0, fmt.Errorf("has an RSA key of %d bits, want 2048 to 4096", bits)
		}
		return x509.SHA256WithRSA, nil
	}
	return 0, fmt.Errorf("has an unsupported key type %T, want ECDSA or RSA", pub)
}

func isPSS(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	}
	return false
}

// SubjectKeyID returns the RFC 5280 section 4.2.1.2 method 1 key identifier of
// a public key: the SHA-1 digest of its subjectPublicKey bit string.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, err
	}
	sum := sha1.Sum(info.Key.Bytes)
	return sum[:], nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// checkSubjectAltName allows no names, or the single URI spiffe://<trust
// domain>. It reads the extension itself because Go ignores the name forms
// it does not know.
func checkSubjectAltName(cert *x509.Certificate, td spiffeid.TrustDomain) error {
	ext, ok := extension(cert, oidSubjectAltName)
	if !ok {
		return nil
	}
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) > 0 {
		return errors.New("its subjectAltName does not parse")
	}
	var names []asn1.RawValue
	for body := seq.Bytes; len(body) > 0; {
		var n asn1.RawValue
		var err error
		if body, err = asn1.Unmarshal(body, &n); err != nil {
			return errors.New("its subjectAltName does not parse")
		}
		names = append(names, n)
	}
	if len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != tagURI || string(names[0].Bytes) != td.IDString() {
		return fmt.Errorf("its subjectAltName, when present, must be exactly the one URI %s", td.IDString())
	}
	return nil
}

// checkProfile checks a signing CA certificate against the profile of SPEC
// section 2.5. Whether it chains to an anchor is a separate question.
func checkProfile(cert *x509.Certificate, td spiffeid.TrustDomain) error {
	if cert.Version != 3 {
		return errors.New("is not an X.509 version 3 certificate")
	}
	if bytes.Equal(cert.RawSubject, emptyName) {
		return errors.New("has an empty subject")
	}
	if len(cert.SubjectKeyId) == 0 {
		return errors.New("has no subjectKeyIdentifier")
	}
	if err := checkSubjectAltName(cert, td); err != nil {
		return err
	}
	want, err := keySignatureAlgorithm(cert.PublicKey)
	if err != nil {
		return err
	}
	if isPSS(cert.SignatureAlgorithm) {
		return errors.New("is signed with RSASSA-PSS, which is not used")
	}
	if isSelfSigned(cert) && cert.SignatureAlgorithm != want {
		return fmt.Errorf("is self-signed with %s, want %s", cert.SignatureAlgorithm, want)
	}
	bc, ok := extension(cert, oidBasicConstraints)
	if !ok || !bc.Critical || !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		return errors.New("its basicConstraints must be critical with cA true and pathLenConstraint 0")
	}
	ku, ok := extension(cert, oidKeyUsage)
	if !ok || !ku.Critical || cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return errors.New("its keyUsage must be critical with keyCertSign and cRLSign only")
	}
	if err := checkNameConstraints(cert, td); err != nil {
		return err
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		return fmt.Errorf("has a critical extension this issuer does not know: %v", cert.UnhandledCriticalExtensions)
	}
	if len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) > 0 {
		anyUsage := slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny)
		both := slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		if !anyUsage && !both {
			return errors.New("its extendedKeyUsage limits the certificates it signs to something other than serverAuth and clientAuth, which X.509-SVIDs carry")
		}
	}
	return nil
}

// emptyName is the DER encoding of a name without attributes.
var emptyName = []byte{0x30, 0x00}

// checkAnchor checks a root certificate the operator supplies, or a
// self-signed CA certificate kept in the CA directory without its key. A
// root is the operator's own: it needs to be a CA that signed itself, and
// either carry the full name constraints of the profile or be declared
// dedicated to it (SPEC section 2.5.1).
func checkAnchor(cert *x509.Certificate, td spiffeid.TrustDomain, dedicated bool) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("is not a CA certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("has a keyUsage without keyCertSign")
	}
	if !isSelfSigned(cert) {
		return errors.New("is not self-signed: list the root that signed it instead")
	}
	if isPSS(cert.SignatureAlgorithm) {
		return errors.New("is signed with RSASSA-PSS, which is not used")
	}
	if !dedicated && !fencesTrustDomain(cert, td) {
		return fmt.Errorf("does not carry the full name constraints of SPEC section 2.5 for %s, and ca_roots_dedicated is not set: a CA under the root could then certify any name that a verifier of this trust domain accepts", td)
	}
	return nil
}
