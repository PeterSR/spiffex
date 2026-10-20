// Command goissue gets an X.509-SVID for a key of a chosen type, which neither
// the agent (P-256 only) nor "spiffex token -x509" (P-256 only) can ask for.
// It uses spiffex's own issuer client with go-spiffe to check the answer, and
// writes what a workload would keep:
//
//	goissue ALG ISSUER TRUST_DOMAIN CLIENT_ID KEYFILE DIR
//
// ALG is P-256, P-384, Ed25519 or RSA-2048. KEYFILE is the workload's
// credential, as for "spiffex token". DIR gets key.pem (PKCS#8) and chain.pem.
// It prints the SPIFFE ID. Exit status 1 on any failure.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "goissue:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func newKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "P-256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case "RSA-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return nil, fmt.Errorf("unknown key type %q", alg)
}

func run(ctx context.Context, args []string) (string, error) {
	if len(args) != 6 {
		return "", fmt.Errorf("usage: goissue ALG ISSUER TRUST_DOMAIN CLIENT_ID KEYFILE DIR")
	}
	alg, issuer, tdName, clientID, keyFile, dir := args[0], args[1], args[2], args[3], args[4], args[5]
	td, err := spiffeid.TrustDomainFromString(tdName)
	if err != nil {
		return "", err
	}
	key, err := newKey(alg)
	if err != nil {
		return "", err
	}
	credKey, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	parsed, err := keyset.ParsePrivateKey(credKey)
	if err != nil {
		return "", err
	}
	client, err := agent.Discover(ctx, issuer, td, nil)
	if err != nil {
		return "", err
	}
	svid, err := client.FetchX509SVID(ctx, agent.PrivateKeyJWT{ClientID: clientID, Key: parsed}, key)
	if err != nil {
		return "", err
	}
	bundle, err := client.FetchBundle(ctx)
	if err != nil {
		return "", err
	}
	if _, _, err := x509svid.Verify(svid.Chain, bundle); err != nil {
		return "", fmt.Errorf("the answer does not verify against the bundle: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var chain []byte
	for _, c := range svid.Chain {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "chain.pem"), chain, 0o644); err != nil {
		return "", err
	}
	return svid.SPIFFEID.String(), nil
}
