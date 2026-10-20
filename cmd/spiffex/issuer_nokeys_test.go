package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// An issuer with a CA starts with an empty keys_dir and serves X.509-SVIDs
// through the token command, which always fetches the bundle; JWT-SVIDs wait
// for a key, which the running issuer picks up, and stop again when it is
// removed. Without a CA the same directory is a startup failure.
func TestIssuerWithoutJWTKeys(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	dir := filepath.Dir(config)
	keysDir := filepath.Join(dir, "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the settings helper changed: %v", err)
	}
	if err := os.Remove(filepath.Join(keysDir, entries[0].Name())); err != nil {
		t.Fatal(err)
	}

	workload, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&workload.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	writeFile(t, dir, "state.yaml", "origins:\n  dev:\n    provider: keys\n    members:\n      billing: { keys: ["+string(pub)+"] }\n")
	keyData, err := keyset.MarshalPrivateKey(workload)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writeFile(t, dir, "workload.key", string(keyData))

	args := []string{"-config", config, "-listen", strings.TrimPrefix(url, "http://")}
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runIssuer(context.Background(), args); err == nil || !strings.Contains(err.Error(), "certificate authority") {
		t.Errorf("no key and an empty ca_dir: %v", err)
	}
	if err := os.Remove(caDir); err != nil {
		t.Fatal(err)
	}
	noCA := writeFile(t, dir, "noca.yaml", "issuer: "+url+"\ntrust_domain: example.org\nkeys_dir: keys\nstate: { file: state.yaml }\n")
	if err := runIssuer(context.Background(), []string{"-config", noCA, "-listen", strings.TrimPrefix(url, "http://")}); err == nil || !strings.Contains(err.Error(), "signing keys") {
		t.Errorf("no key and no CA: %v", err)
	}

	if _, err := ca.Init(caDir, caTD, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	startTestIssuer(t, config, url)

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	getJSON(t, url+"/jwks", &jwks)
	if len(jwks.Keys) != 0 {
		t.Errorf("the JWKS holds %d keys", len(jwks.Keys))
	}
	if n := bundleX509Keys(t, url); n != 1 {
		t.Errorf("%d X.509 authorities in the bundle, want 1", n)
	}

	out := t.TempDir()
	keyOut, certOut, bundleOut := filepath.Join(out, "key.pem"), filepath.Join(out, "cert.pem"), filepath.Join(out, "bundle.pem")
	x509Args := []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-x509", "-key-out", keyOut, "-cert-out", certOut, "-bundle-out", bundleOut}
	if err := runToken(context.Background(), x509Args); err != nil {
		t.Fatalf("token -x509 without a JWT key: %v", err)
	}
	if _, _, err := x509svid.Verify(pemCerts(t, certOut), x509bundle.FromX509Authorities(caTD, pemCerts(t, bundleOut))); err != nil {
		t.Errorf("go-spiffe refuses the certificate: %v", err)
	}

	jwtArgs := []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-audience", "orders"}
	if err := runToken(context.Background(), jwtArgs); err == nil || !strings.Contains(err.Error(), "no JWT-SVIDs") {
		t.Errorf("JWT-SVID without a key: %v", err)
	}

	added, err := keyset.Add(keysDir, keyset.ES256, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the issuer to sign JWT-SVIDs with the added key", func() bool {
		return runToken(context.Background(), jwtArgs) == nil
	})
	if err := os.Remove(filepath.Join(keysDir, added.File)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the issuer to stop signing JWT-SVIDs", func() bool {
		return runToken(context.Background(), jwtArgs) != nil
	})
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
