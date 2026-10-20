package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func runToken(ctx context.Context, args []string) error {
	fs := newFlagSet("token", "-issuer URL (-audience AUD | -x509 -key-out FILE -cert-out FILE [-bundle-out FILE]) "+credentialSynopsis+" [flags]")
	creds := addCredentialFlags(fs)
	var audiences stringList
	fs.Var(&audiences, "audience", "audience of the JWT-SVID (required without -x509; repeat for several)")
	x509Flag := fs.Bool("x509", false, "fetch an X.509-SVID for a new P-256 key instead of a JWT-SVID")
	keyOut := fs.String("key-out", "", "with -x509: file to write the private key to (required; must not exist; mode 0600)")
	certOut := fs.String("cert-out", "", "with -x509: file to write the certificate chain to (required; must not exist)")
	bundleOut := fs.String("bundle-out", "", "with -x509: file to write the trust domain's X.509 authorities to (must not exist)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch {
	case *x509Flag && len(audiences) > 0:
		return usageError{errors.New("-audience does not go with -x509: an X.509-SVID has no audience")}
	case *x509Flag && (*keyOut == "" || *certOut == ""):
		return usageError{errors.New("-key-out and -cert-out are required with -x509")}
	case !*x509Flag && (*keyOut != "" || *certOut != "" || *bundleOut != ""):
		return usageError{errors.New("-key-out, -cert-out and -bundle-out go only with -x509")}
	case !*x509Flag && len(audiences) == 0:
		return usageError{errors.New("-audience is required")}
	}
	cred, err := creds.credential()
	if err != nil {
		return err
	}
	td, httpClient, err := creds.issuerTarget()
	if err != nil {
		return err
	}
	client, err := agent.Discover(ctx, *creds.issuerURL, td, httpClient)
	if err != nil {
		return err
	}
	if *x509Flag {
		return fetchX509(ctx, client, cred, *keyOut, *certOut, *bundleOut)
	}
	token, err := client.FetchToken(ctx, cred, audiences)
	if err != nil {
		return err
	}
	fmt.Println(token.Value)
	return nil
}

// outputFile is a file reserved for the results with O_EXCL.
type outputFile struct {
	path string
	f    *os.File
}

// reserveOutputs creates every output file, empty and exclusively, so that
// nothing the issuer's answer is worth can fail to be kept for a reason known
// beforehand: a path that exists, a missing or unwritable directory, two
// equal paths. On a failure it removes what it created.
func reserveOutputs(key, cert, bundle string) ([]*outputFile, error) {
	var files []*outputFile
	remove := func() {
		for _, o := range files {
			o.f.Close()
			_ = os.Remove(o.path)
		}
	}
	for _, p := range []struct {
		path string
		mode os.FileMode
	}{{key, 0o600}, {cert, 0o644}, {bundle, 0o644}} {
		if p.path == "" {
			continue
		}
		f, err := os.OpenFile(p.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, p.mode)
		if err != nil {
			remove()
			return nil, err
		}
		files = append(files, &outputFile{path: p.path, f: f})
	}
	return files, nil
}

// fetchX509 makes a key in memory, has the issuer certify it and writes the
// results. Everything that can fail without costing the issuer a certificate
// is done first: the output files are created and the bundle fetched. They
// are written only once the chain has verified against the bundle, and a
// failure leaves none of them behind.
func fetchX509(ctx context.Context, client *agent.IssuerClient, cred agent.Credential, keyOut, certOut, bundleOut string) (err error) {
	files, err := reserveOutputs(keyOut, certOut, bundleOut)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			for _, o := range files {
				o.f.Close()
				_ = os.Remove(o.path)
			}
		}
	}()
	bundle, err := client.FetchBundle(ctx)
	if err != nil {
		return err
	}
	if len(bundle.X509Authorities()) == 0 {
		return errors.New("the trust domain's bundle has no X.509 authorities")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	svid, err := client.FetchX509SVID(ctx, cred, key)
	if err != nil {
		return err
	}
	if _, _, err := x509svid.Verify(svid.Chain, bundle); err != nil {
		return fmt.Errorf("the issued certificate does not verify against the issuer's bundle: %w", err)
	}
	keyPEM, err := keyset.MarshalPrivateKey(key)
	if err != nil {
		return err
	}
	var chain, authorities []byte
	for _, c := range svid.Chain {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	for _, c := range bundle.X509Authorities() {
		authorities = append(authorities, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	contents := [][]byte{keyPEM, chain}
	if bundleOut != "" {
		contents = append(contents, authorities)
	}
	for i, o := range files {
		if _, err := o.f.Write(contents[i]); err != nil {
			return err
		}
		if err := o.f.Close(); err != nil {
			return err
		}
	}
	fmt.Printf("issued %s until %s: key %s, certificate %s\n", svid.SPIFFEID, svid.Chain[0].NotAfter.UTC().Format("2006-01-02T15:04:05Z"), keyOut, certOut)
	return nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return fmt.Sprint([]string(*l)) }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
