package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/keyset"
)

// timeLayout is the creation time format embedded in file names.
const timeLayout = "20060102T150405Z"

var fileNamePattern = regexp.MustCompile(`^ca-(\d{8}T\d{6}Z)\.(crt|key)$`)

// maxChainLength bounds the certificates in one certificate file.
const maxChainLength = 8

// Options say where the CA lives and the settings that decide how it
// rotates. They are the issuer's settings (section 2.5 of the SPEC).
type Options struct {
	// Dir is the CA directory (ca_dir).
	Dir string
	// Roots is the file of the operator's root certificates (ca_roots), or
	// empty.
	Roots string
	// RootsDedicated is ca_roots_dedicated.
	RootsDedicated bool
	TrustDomain    spiffeid.TrustDomain
	// ActivationDelay is how long a new anchor is published before the issuer
	// issues anything that chains to it.
	ActivationDelay time.Duration
	// Retention is how long an anchor stays published after the last use of
	// its CAs. See Retention.
	Retention time.Duration
	// Warn, when set, receives the warnings Import has for the operator.
	Warn func(message string)
}

func (o Options) check() error {
	switch {
	case o.Dir == "":
		return errors.New("the CA directory is required")
	case o.TrustDomain.IsZero():
		return errors.New("the trust domain is required")
	case o.ActivationDelay <= 0 || o.Retention <= 0:
		return errors.New("the activation delay and the retention must be positive")
	}
	return nil
}

// CertFileName returns the certificate file name for a CA made at the given
// time, and KeyFileName its key file name.
func CertFileName(created time.Time) string { return "ca-" + created.UTC().Format(timeLayout) + ".crt" }

// KeyFileName is CertFileName for the key file.
func KeyFileName(created time.Time) string { return "ca-" + created.UTC().Format(timeLayout) + ".key" }

// stemFiles are the files of one CA generation.
type stemFiles struct {
	stem    string
	created time.Time
	cert    string
	key     string
}

// scanDir lists the CA generations in dir, in file name order. Files that do
// not match the pattern are ignored, so the directory can hold other things
// (a Kubernetes Secret mount has hidden ..data entries, for one).
func scanDir(dir string) ([]*stemFiles, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*stemFiles
	byStem := map[string]*stemFiles{}
	for _, e := range entries {
		m := fileNamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		created, err := time.Parse(timeLayout, m[1])
		if err != nil {
			return nil, fmt.Errorf("%s: bad creation time in file name: %w", e.Name(), err)
		}
		sf := byStem[m[1]]
		if sf == nil {
			sf = &stemFiles{stem: m[1], created: created}
			byStem[m[1]] = sf
			out = append(out, sf)
		}
		if m[2] == "crt" {
			sf.cert = e.Name()
		} else {
			sf.key = e.Name()
		}
	}
	return out, nil
}

// Pending returns the key files in dir that wait for a signed certificate:
// the keys of certificate requests made with spiffex ca csr.
func Pending(dir string) ([]string, error) {
	stems, err := scanDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sf := range stems {
		if sf.cert == "" && sf.key != "" {
			out = append(out, sf.key)
		}
	}
	return out, nil
}

// parseCertificates reads the certificates of a PEM file, at most limit of
// them, and refuses any other block, a private key above all: it would be a
// secret in a file meant to be public.
func parseCertificates(data []byte, limit int) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("a %q PEM block where only certificates belong", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		if len(certs) > limit {
			return nil, fmt.Errorf("more than %d certificates", limit)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}
	if len(bytes.TrimSpace(data)) > 0 {
		return nil, errors.New("data that is not PEM after the certificates")
	}
	return certs, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// item is a CA generation as read from disk, before its chain is judged.
type item struct {
	files     *stemFiles
	published time.Time
	chain     []*x509.Certificate
	signer    crypto.Signer
}

// itemError says which item failed: a CA generation by its stem, or the
// roots file.
type itemError struct {
	key string
	err error
	// keyGone is true when the generation has a certificate and no key: its
	// key was removed, or never was there.
	keyGone bool
	// skippable marks a generation that startup leaves out with a warning
	// instead of failing: a certificate that is no anchor and has lost its
	// key, which is how a compromised intermediate is taken out of service.
	skippable bool
}

func (e itemError) Error() string { return e.err.Error() }

func (e itemError) Unwrap() error { return e.err }

// rootsKey is the itemError key of the ca_roots file as a whole.
const rootsKey = "ca_roots"

// reading is what a pass over the CA directory and the roots file found.
type reading struct {
	cas     []CA
	anchors []Anchor
	// rootsFailed is true when ca_roots could not be read at all.
	rootsFailed bool
	errs        []itemError
}

func modTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime().UTC(), nil
}

// read loads everything: the operator's roots, then every CA generation in
// the directory, each judged on its own. Problems are collected in errs
// rather than stopping the pass, because what to do about one depends on
// whether the issuer is starting or running.
func read(opts Options) (*reading, error) { return readWith(opts, nil) }

// readWith is read for a running issuer: incumbents holds the IDs of the CAs
// in service, which keep their subject against a newcomer.
func readWith(opts Options, incumbents map[string]bool) (*reading, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}
	stems, err := scanDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	r := &reading{}
	byID := map[string]int{}
	addAnchor := func(a Anchor) {
		if i, dup := byID[a.ID]; dup {
			// The same certificate in two places is published once, from
			// the earlier of the two.
			if a.Published.Before(r.anchors[i].Published) {
				r.anchors[i].Published = a.Published
			}
			return
		}
		byID[a.ID] = len(r.anchors)
		r.anchors = append(r.anchors, a)
	}

	if opts.Roots != "" {
		r.readRoots(opts, addAnchor)
	}

	var signing []*item
	for _, sf := range stems {
		if sf.cert == "" {
			continue
		}
		it, err := readItem(opts.Dir, sf)
		if err != nil {
			r.errs = append(r.errs, itemError{key: sf.stem, err: err})
			continue
		}
		if it.signer == nil {
			// Without a key it is an anchor or nothing.
			if !isSelfSigned(it.chain[0]) || len(it.chain) > 1 {
				err := fmt.Errorf("%s has no key file (%s), so its key was removed or never came back: it does not sign. Delete the certificate too, or put the key back", sf.cert, KeyFileName(sf.created))
				r.errs = append(r.errs, itemError{key: sf.stem, err: err, keyGone: true, skippable: true})
				continue
			}
			if err := checkAnchor(it.chain[0], opts.TrustDomain, false); err != nil {
				r.errs = append(r.errs, itemError{sf.stem, fmt.Errorf("%s has no key file (%s) and %w", sf.cert, KeyFileName(sf.created), err), true, false})
				continue
			}
			addAnchor(Anchor{ID: certID(it.chain[0]), Cert: it.chain[0], Published: it.published, Source: sf.cert})
			continue
		}
		signing = append(signing, it)
	}

	// A self-signed signing CA is its own anchor. Each is judged alone, and
	// only the ones that pass are anchors and in the pool an intermediate
	// chains to: a root that fails the profile must not carry anything.
	var others []*item
	for _, it := range signing {
		if len(it.chain) > 1 || !isSelfSigned(it.chain[0]) {
			others = append(others, it)
			continue
		}
		c, err := judge(opts.TrustDomain, it, nil)
		if err != nil {
			r.errs = append(r.errs, itemError{key: it.files.stem, err: fmt.Errorf("%s: %w", it.files.cert, err)})
			continue
		}
		r.cas = append(r.cas, c)
		addAnchor(Anchor{ID: certID(it.chain[0]), Cert: it.chain[0], Published: it.published, Source: it.files.cert})
	}
	var pool []*x509.Certificate
	for _, a := range r.anchors {
		pool = append(pool, a.Cert)
	}
	for _, it := range others {
		c, err := judge(opts.TrustDomain, it, pool)
		if err != nil {
			r.errs = append(r.errs, itemError{key: it.files.stem, err: fmt.Errorf("%s: %w", it.files.cert, err)})
			continue
		}
		r.cas = append(r.cas, c)
	}
	r.refuseSharedSubjects(incumbents)
	return r, nil
}

// sharedSubject returns a certificate in cas or anchors that has c's subject
// with a different key, or nil. The subject must differ between CA generations
// (SPEC section 2.5), or the issuer names of the certificates they sign are
// ambiguous.
func sharedSubject(c *x509.Certificate, cas []CA, anchors []Anchor) *x509.Certificate {
	same := func(other *x509.Certificate) bool {
		return bytes.Equal(other.RawSubject, c.RawSubject) && !publicKeysEqual(other.PublicKey, c.PublicKey)
	}
	for _, a := range anchors {
		if same(a.Cert) {
			return a.Cert
		}
	}
	for _, other := range cas {
		if same(other.Cert) {
			return other.Cert
		}
	}
	return nil
}

func sharedSubjectError(c *x509.Certificate, file string) error {
	return fmt.Errorf("%s: its subject %s is also the subject of another CA with a different key, but the subject must differ between CA generations (SPEC section 2.5)", file, c.Subject)
}

// refuseSharedSubjects fails the CAs whose subject another CA or anchor with a
// different key already has. A CA in service keeps its name against a
// newcomer; among the rest the older generation keeps it.
func (r *reading) refuseSharedSubjects(incumbents map[string]bool) {
	slices.SortStableFunc(r.cas, func(a, b CA) int {
		if ia, ib := incumbents[a.ID], incumbents[b.ID]; ia != ib {
			if ia {
				return -1
			}
			return 1
		}
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return compareStrings(a.ID, b.ID)
	})
	// The anchor of a self-signed CA is judged through the CA itself: left
	// in, a newcomer's own anchor would make the CA in service the one refused.
	var others []Anchor
	for _, a := range r.anchors {
		if !slices.ContainsFunc(r.cas, func(c CA) bool { return c.SelfSigned() && certID(c.Cert) == a.ID }) {
			others = append(others, a)
		}
	}
	var kept []CA
	for _, c := range r.cas {
		if sharedSubject(c.Cert, kept, others) == nil {
			kept = append(kept, c)
			continue
		}
		r.errs = append(r.errs, itemError{key: stemOf(c.File), err: sharedSubjectError(c.Cert, c.File)})
		if c.SelfSigned() {
			id := certID(c.Cert)
			r.anchors = slices.DeleteFunc(r.anchors, func(a Anchor) bool { return a.ID == id })
		}
	}
	r.cas = kept
}

func (r *reading) readRoots(opts Options, add func(Anchor)) {
	fail := func(err error) {
		r.rootsFailed = true
		r.errs = append(r.errs, itemError{key: rootsKey, err: fmt.Errorf("%s: %w", opts.Roots, err)})
	}
	data, err := os.ReadFile(opts.Roots)
	if err != nil {
		fail(err)
		return
	}
	mtime, err := modTime(opts.Roots)
	if err != nil {
		fail(err)
		return
	}
	certs, err := parseCertificates(data, maxRoots)
	if err != nil {
		fail(err)
		return
	}
	for _, cert := range certs {
		if err := checkAnchor(cert, opts.TrustDomain, opts.RootsDedicated); err != nil {
			r.errs = append(r.errs, itemError{key: rootsKey, err: fmt.Errorf("%s: the certificate %s (%s) %w", opts.Roots, certID(cert)[:16], cert.Subject, err)})
			continue
		}
		add(Anchor{ID: certID(cert), Cert: cert, Published: mtime, Source: RootsSource})
	}
}

// maxRoots bounds the certificates in the roots file.
const maxRoots = 64

func readItem(dir string, sf *stemFiles) (*item, error) {
	certPath := filepath.Join(dir, sf.cert)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	chain, err := parseCertificates(data, maxChainLength)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sf.cert, err)
	}
	mtime, err := modTime(certPath)
	if err != nil {
		return nil, err
	}
	it := &item{files: sf, chain: chain, published: sf.created}
	// A file name can claim any age; the modification time says when the
	// certificate arrived here, which is what activation must count from.
	if mtime.After(it.published) {
		it.published = mtime
	}
	if sf.key != "" {
		keyData, err := os.ReadFile(filepath.Join(dir, sf.key))
		if err != nil {
			return nil, err
		}
		if it.signer, err = keyset.DecodePrivateKey(keyData); err != nil {
			return nil, fmt.Errorf("%s: %w", sf.key, err)
		}
		if !publicKeysEqual(it.signer.Public(), chain[0].PublicKey) {
			return nil, fmt.Errorf("%s does not hold the key of %s", sf.key, sf.cert)
		}
	}
	return it, nil
}

// judge decides whether a certificate with its key is a CA the issuer may
// sign with: it meets the profile, and an X.509-SVID it signs verifies
// against an anchor.
func judge(td spiffeid.TrustDomain, it *item, anchors []*x509.Certificate) (CA, error) {
	signing := it.chain[0]
	if err := checkProfile(signing, td); err != nil {
		return CA{}, fmt.Errorf("does not meet the CA profile (SPEC section 2.5): %w", err)
	}
	if len(it.chain) > 1 && isSelfSigned(signing) {
		return CA{}, errors.New("is self-signed and stands alone in its file, but the file holds more certificates")
	}
	// The name says when the request was made; the certificate says when it
	// was signed, and a later import of an earlier request must not rank
	// older than the CA it replaces.
	created := it.files.created
	if signing.NotBefore.After(created) {
		created = signing.NotBefore.UTC()
	}
	c := CA{
		ID:        certID(signing),
		Created:   created,
		Published: it.published,
		Cert:      signing,
		Signer:    it.signer,
		File:      it.files.cert,
		KeyFile:   it.files.key,
	}
	if isSelfSigned(signing) {
		anchors = []*x509.Certificate{signing}
	}
	chain, err := chainToAnchor(td, signing, it.signer, it.chain[1:], anchors)
	if err != nil {
		return CA{}, err
	}
	c.Anchor = chain[len(chain)-1]
	c.Chain = chain[:len(chain)-1]
	if len(chain) == 1 {
		c.Chain = chain
	}
	return c, nil
}

// chainToAnchor builds the path from a CA certificate through the middle
// certificates the operator supplied to one of the anchors, and returns it,
// the CA first and the anchor last. It does so by verifying an X.509-SVID
// made for the purpose and signed with the CA's key, so that every
// constraint on the path, name constraints and path lengths above all, is
// judged as a verifier will judge it, with the CA counted as the
// intermediate it will be.
//
// The path is judged at a moment all its certificates are valid, if there is
// one: whether a CA has expired is a question for when it signs, not for
// whether its chain is sound.
func chainToAnchor(td spiffeid.TrustDomain, signing *x509.Certificate, signer crypto.Signer, middles, anchors []*x509.Certificate) ([]*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, a := range anchors {
		roots.AddCert(a)
	}
	inter := x509.NewCertPool()
	inter.AddCert(signing)
	for _, m := range middles {
		inter.AddCert(m)
	}
	moments := []time.Time{signing.NotBefore}
	for _, c := range append(slices.Clone(middles), anchors...) {
		moments = append(moments, c.NotBefore)
	}
	slices.SortFunc(moments, func(a, b time.Time) int { return b.Compare(a) })
	moments = slices.CompactFunc(moments, time.Time.Equal)

	var chain []*x509.Certificate
	var err error
	for _, at := range moments {
		if chain, err = verifyProbe(td, signing, signer, roots, inter, at); err == nil {
			break
		}
	}
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return nil, errors.New("does not chain to an anchor: neither a root in ca_roots nor a self-signed CA in ca_dir signed it (or a CA between them is missing from the file)")
		}
		return nil, fmt.Errorf("does not chain to an anchor: %w", err)
	}
	for _, m := range middles {
		if !slices.ContainsFunc(chain, m.Equal) {
			return nil, fmt.Errorf("the certificate %s in the file is not on the path from the CA to an anchor", certID(m)[:16])
		}
	}
	for _, c := range chain[:len(chain)-1] {
		if isPSS(c.SignatureAlgorithm) {
			return nil, errors.New("has a certificate signed with RSASSA-PSS on its path, which is not used")
		}
	}
	return chain, nil
}

// verifyProbe signs an X.509-SVID for a throwaway key with the CA's key and
// verifies it at the given moment, as a client and as a server, returning the
// path from the CA to the anchor.
func verifyProbe(td spiffeid.TrustDomain, signing *x509.Certificate, signer crypto.Signer, roots, inter *x509.CertPool, at time.Time) ([]*x509.Certificate, error) {
	probeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := spiffeid.FromPath(td, "/spiffex-probe")
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
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             at.Add(-time.Minute),
		NotAfter:              at.Add(time.Hour),
		URIs:                  []*url.URL{uri},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signing, probeKey.Public(), signer)
	if err != nil {
		return nil, err
	}
	probe, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	var path []*x509.Certificate
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		chains, err := probe.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil {
			return nil, err
		}
		path = chains[0][1:]
	}
	return path, nil
}

// NoKeyWarning begins the warning Load gives when no CA has a key but anchors
// remain; the issuer logs that one as an error, since X.509-SVIDs are not
// offered.
const NoKeyWarning = "no CA with a key in"

// Load reads the CA directory and the roots file once, as the issuer does when
// it starts: every problem is an error. now decides which anchors have been
// retained long enough.
func Load(opts Options, now time.Time) (*Set, error) {
	r, err := read(opts)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, e := range r.errs {
		if e.skippable && opts.Warn != nil {
			opts.Warn(fmt.Sprintf("not using a CA certificate: %s", e.err))
		}
		if !e.skippable {
			errs = append(errs, e)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(r.cas) == 0 {
		if len(r.anchors) == 0 {
			return nil, fmt.Errorf("no CA with a key (ca-<YYYYMMDDTHHMMSSZ>.crt and .key) and no anchor in %s: make one with spiffex ca init, or ca csr and ca import", opts.Dir)
		}
		// Every key was removed, the compromise response of SPEC section
		// 2.4. The anchors stay published, as the running issuer does it.
		if opts.Warn != nil {
			opts.Warn(fmt.Sprintf("%s %s: a key file is missing or was removed, so the issuer publishes the anchors and signs no X.509-SVIDs until a CA with a key is added (spiffex ca init, or ca csr and ca import)", NoKeyWarning, opts.Dir))
		}
	}
	set, err := newSet(r.cas, r.anchors, opts.ActivationDelay, opts.Retention, now, nil)
	if err != nil {
		return nil, err
	}
	if opts.Warn != nil {
		if c, ok := set.Signing(now); ok {
			skipped := slices.ContainsFunc(r.errs, func(e itemError) bool { return e.skippable })
			for _, a := range r.anchors {
				// A keyless root newer than the signing CA is one whose key was removed.
				if a.Source != RootsSource && !slices.ContainsFunc(r.cas, func(x CA) bool { return x.File == a.Source }) && stemOf(a.Source) > stemOf(c.File) {
					skipped = true
				}
			}
			if skipped {
				opts.Warn(fmt.Sprintf("%s signs now, with a newer CA left out for want of a key. If the root it chains to had left the bundle, verifiers may reject what it signs for up to activation_delay (%s): prune the older CAs after removing a key, and wait before restarting", c.File, opts.ActivationDelay))
			}
		}
	}
	return set, nil
}

// Algorithm describes the CA's key: P-256, P-384 or RSA-<bits>.
func (c CA) Algorithm() string {
	switch k := c.Cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	}
	return "unknown"
}
