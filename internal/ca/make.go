package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/keyset"
)

// ES384 is the algorithm of a CA key on P-256's bigger sibling, P-384. ES256
// (P-256) and RS256 (RSA, 3072 bits) are keyset's.
const ES384 keyset.Algorithm = "ES384"

// MinRootLifetime is the shortest validity Init accepts: a root that ends
// within the lifetime of an X.509-SVID shortens every certificate it signs.
const MinRootLifetime = 24 * time.Hour

// DefaultRootLifetime is how long a root made by Init is valid: nothing renews
// it, so it is long.
const DefaultRootLifetime = 5 * 365 * 24 * time.Hour

func generate(alg keyset.Algorithm) (crypto.Signer, error) {
	if alg == ES384 {
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	return keyset.Generate(alg)
}

// caName is the subject of a new CA: the trust domain as the organization when
// it fits, and a common name that is unique per generation, so that the
// certificates of two generations never share an issuer name.
func caName(td spiffeid.TrustDomain, created time.Time) ([]byte, error) {
	var org string
	if len(td.Name()) <= MaxNameLength {
		org = td.Name()
	}
	unique := make([]byte, 4)
	if _, err := rand.Read(unique); err != nil {
		return nil, err
	}
	return Name(org, fmt.Sprintf("spiffex CA %s-%x", created.UTC().Format(timeLayout), unique))
}

// profileExtensions are the extensions of the CA profile that are not simple
// template fields, for a certificate request to carry.
func profileExtensions(td spiffeid.TrustDomain) ([]pkix.Extension, error) {
	bc, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{true, 0})
	if err != nil {
		return nil, err
	}
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7})
	if err != nil {
		return nil, err
	}
	nc, err := NameConstraints(td)
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{
		{Id: oidBasicConstraints, Critical: true, Value: bc},
		{Id: oidKeyUsage, Critical: true, Value: ku},
		nc,
	}, nil
}

// SerialNumber returns a certificate serial number: 128 random bits with the
// top bit cleared, so that it is positive and at most 20 octets long.
func SerialNumber() (*big.Int, error) {
	for {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		b[0] &= 0x7f
		if n := new(big.Int).SetBytes(b); n.Sign() > 0 {
			return n, nil
		}
	}
}

func certificatePEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// Init makes a self-signed root for the trust domain: a P-256 key and a
// certificate that meets the profile of SPEC section 2.5, valid for validFor
// from now, written to dir as a new generation. It makes dir if it does not
// exist.
func Init(dir string, td spiffeid.TrustDomain, now time.Time, validFor time.Duration) (CA, error) {
	if td.IsZero() {
		return CA{}, errors.New("the trust domain is required")
	}
	if validFor < MinRootLifetime {
		return CA{}, fmt.Errorf("a root valid for %s is too short: make it valid for at least %s", validFor, MinRootLifetime)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return CA{}, err
	}
	created := now.UTC().Truncate(time.Second)
	signer, err := generate(keyset.ES256)
	if err != nil {
		return CA{}, err
	}
	subject, err := caName(td, created)
	if err != nil {
		return CA{}, err
	}
	serial, err := SerialNumber()
	if err != nil {
		return CA{}, err
	}
	ski, err := SubjectKeyID(signer.Public())
	if err != nil {
		return CA{}, err
	}
	nc, err := NameConstraints(td)
	if err != nil {
		return CA{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            subject,
		NotBefore:             created.Add(-time.Minute),
		NotAfter:              created.Add(validFor),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		ExtraExtensions:       []pkix.Extension{nc},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return CA{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CA{}, err
	}
	if err := checkProfile(cert, td); err != nil {
		return CA{}, fmt.Errorf("the certificate made does not meet the CA profile: %w", err)
	}
	keyPEM, err := keyset.MarshalPrivateKey(signer)
	if err != nil {
		return CA{}, err
	}
	// The key goes first: a certificate without a key is not used, and a key
	// without a certificate is only a pending request.
	if err := writeNew(dir, KeyFileName(created), keyPEM, 0o600); err != nil {
		return CA{}, err
	}
	if err := writeNew(dir, CertFileName(created), certificatePEM(cert), 0o644); err != nil {
		_ = os.Remove(filepath.Join(dir, KeyFileName(created)))
		return CA{}, err
	}
	return CA{ID: certID(cert), Created: created, Published: created, Cert: cert, Chain: []*x509.Certificate{cert}, Anchor: cert,
		Signer: signer, File: CertFileName(created), KeyFile: KeyFileName(created)}, nil
}

// NewCSR makes a key for an intermediate CA and a certificate request for it,
// to be signed by the operator's CA. The key is written to dir as a pending
// generation; Import installs the certificate. The request carries the
// profile's extensions, which a CA is free to ignore: whatever it signs is
// judged against the profile when it is imported.
func NewCSR(dir string, td spiffeid.TrustDomain, alg keyset.Algorithm, now time.Time) (keyFile string, csrPEM []byte, err error) {
	if td.IsZero() {
		return "", nil, errors.New("the trust domain is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	created := now.UTC().Truncate(time.Second)
	signer, err := generate(alg)
	if err != nil {
		return "", nil, err
	}
	subject, err := caName(td, created)
	if err != nil {
		return "", nil, err
	}
	extensions, err := profileExtensions(td)
	if err != nil {
		return "", nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{RawSubject: subject, ExtraExtensions: extensions}, signer)
	if err != nil {
		return "", nil, err
	}
	keyPEM, err := keyset.MarshalPrivateKey(signer)
	if err != nil {
		return "", nil, err
	}
	keyFile = KeyFileName(created)
	if err := writeNew(dir, keyFile, keyPEM, 0o600); err != nil {
		return "", nil, err
	}
	return keyFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Import installs a signed certificate for a pending key. data holds the
// signing CA certificate, then the CA certificates between it and the anchor.
// The certificate must meet the profile and chain to an anchor, or nothing is
// written.
func Import(opts Options, data []byte, now time.Time) (CA, error) {
	if err := opts.check(); err != nil {
		return CA{}, err
	}
	chain, err := parseCertificates(data, maxChainLength)
	if err != nil {
		return CA{}, err
	}
	stems, err := scanDir(opts.Dir)
	if err != nil {
		return CA{}, err
	}
	var it *item
	for _, sf := range stems {
		if sf.key == "" {
			continue
		}
		keyData, err := os.ReadFile(filepath.Join(opts.Dir, sf.key))
		if err != nil {
			return CA{}, err
		}
		signer, err := keyset.DecodePrivateKey(keyData)
		if err != nil || !publicKeysEqual(signer.Public(), chain[0].PublicKey) {
			continue
		}
		if sf.cert != "" {
			return CA{}, fmt.Errorf("%s already has its certificate, %s", sf.key, sf.cert)
		}
		sf.cert = CertFileName(sf.created)
		it = &item{files: sf, chain: chain, signer: signer, published: now}
		break
	}
	if it == nil {
		return CA{}, fmt.Errorf("no key file in %s matches this certificate: it must be the answer to a request made here with spiffex ca csr", opts.Dir)
	}
	r, err := read(opts)
	if err != nil {
		return CA{}, err
	}
	for _, e := range r.errs {
		if e.key == rootsKey {
			return CA{}, fmt.Errorf("cannot check the chain: %w", e)
		}
	}
	var anchors []*x509.Certificate
	for _, a := range r.anchors {
		anchors = append(anchors, a.Cert)
	}
	c, err := judge(opts.TrustDomain, it, anchors)
	if err != nil {
		return CA{}, fmt.Errorf("%s: %w", it.files.cert, err)
	}
	if !now.Before(c.NotAfter()) {
		return CA{}, fmt.Errorf("the certificate chain expired at %s", c.NotAfter().Format(time.RFC3339))
	}
	if clash := sharedSubject(c.Cert, r.cas, r.anchors); clash != nil {
		return CA{}, sharedSubjectError(c.Cert, it.files.cert)
	}
	if opts.Warn != nil {
		if set, err := newSet(r.cas, r.anchors, opts.ActivationDelay, opts.Retention, now, nil); err == nil && set.AnchorRetired(Anchor{ID: certID(c.Anchor)}) {
			opts.Warn(fmt.Sprintf("the root %s left the bundle, since no CA chained to it any more; verifiers may have dropped it. It is published again from the moment the issuer sees this CA, so do not restart the issuer for %s", certID(c.Anchor)[:16], opts.ActivationDelay))
		}
	}
	if err := writeNew(opts.Dir, it.files.cert, certificatePEM(chain...), 0o644); err != nil {
		return CA{}, err
	}
	return c, nil
}

// Prune deletes the files of retired CAs from the directory and returns what
// it removed. It loads the directory first so it acts on what is on disk now.
func Prune(opts Options, now time.Time) ([]CA, error) {
	set, err := Load(opts, now)
	if err != nil {
		return nil, err
	}
	retired := set.Retired()
	for i, c := range retired {
		// The certificate goes first, leaving a pending key and not a
		// certificate nobody can sign with.
		if err := os.Remove(filepath.Join(opts.Dir, c.File)); err != nil {
			return retired[:i], err
		}
		if err := os.Remove(filepath.Join(opts.Dir, c.KeyFile)); err != nil {
			return retired[:i+1], err
		}
	}
	return retired, nil
}

// writeNew writes a file under a temporary name and links it into place, so a
// crash never leaves a half-written file behind and an existing file is never
// overwritten.
func writeNew(dir, name string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, ".ca-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), filepath.Join(dir, name)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists: CA files are named by the second they were made in, so wait a second and try again", name)
		}
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
