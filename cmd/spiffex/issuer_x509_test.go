package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func pemCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		if block, data = pem.Decode(data); block == nil {
			return certs
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
}

// A workload with a registered key gets an X.509-SVID from a running issuer
// through the token command, and go-spiffe accepts it against the bundle the
// command also wrote.
func TestTokenCommandIssuesAnX509SVID(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	dir := filepath.Dir(config)
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
	if _, err := ca.Init(caDir, caTD, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	startTestIssuer(t, config, url)

	out := filepath.Join(t.TempDir(), "svid")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	keyOut, certOut, bundleOut := filepath.Join(out, "key.pem"), filepath.Join(out, "cert.pem"), filepath.Join(out, "bundle.pem")
	args := []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-x509", "-key-out", keyOut, "-cert-out", certOut, "-bundle-out", bundleOut}
	if err := runToken(context.Background(), args); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyOut)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v; want mode 0600", info, err)
	}
	keyPEM, err := os.ReadFile(keyOut)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := keyset.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	chain, bundle := pemCerts(t, certOut), pemCerts(t, bundleOut)
	id, _, err := x509svid.Verify(chain, x509bundle.FromX509Authorities(caTD, bundle))
	if err != nil {
		t.Fatalf("go-spiffe refuses the certificate: %v", err)
	}
	if id.String() != "spiffe://example.org/dev/billing" {
		t.Errorf("SPIFFE ID %s", id)
	}
	if k, ok := chain[0].PublicKey.(*ecdsa.PublicKey); !ok || !k.Equal(issued.Public()) {
		t.Error("the certificate is not for the key that was written")
	}
	if k, ok := issued.Public().(*ecdsa.PublicKey); ok && k.Equal(&workload.PublicKey) {
		t.Error("the SVID key is the workload's registered key")
	}

	// Nothing is overwritten, and a failed request leaves nothing behind.
	if err := runToken(context.Background(), args); err == nil {
		t.Error("the files were overwritten")
	}
	again := filepath.Join(out, "second")
	bad := []string{"-issuer", url, "-client-id", "dev/nobody", "-key-file", keyFile, "-x509", "-key-out", again + ".key", "-cert-out", again + ".crt"}
	if err := runToken(context.Background(), bad); err == nil {
		t.Error("an unknown client got a certificate")
	}
	for _, name := range []string{again + ".key", again + ".crt"} {
		if _, err := os.Stat(name); err == nil {
			t.Errorf("%s was left behind", name)
		}
	}
	// A cert file that exists must not leave the new key behind.
	taken := filepath.Join(out, "taken.crt")
	if err := os.WriteFile(taken, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	clash := []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-x509", "-key-out", filepath.Join(out, "k2.pem"), "-cert-out", taken}
	if err := runToken(context.Background(), clash); err == nil {
		t.Error("an existing certificate file was overwritten")
	}
	if _, err := os.Stat(filepath.Join(out, "k2.pem")); err == nil {
		t.Error("the key was left behind when the certificate could not be written")
	}

	// The JWT-SVID path still works from the same issuer.
	if err := runToken(context.Background(), []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-audience", "orders"}); err != nil {
		t.Errorf("JWT-SVID: %v", err)
	}
}

// The record of an issued X.509-SVID is the only trace of it, so it is
// written at any log level, while other lines below the level are not.
func TestIssuanceIsLoggedAtAnyLevel(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	dir := filepath.Dir(config)
	workload, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&workload.PublicKey)
	pub, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	writeFile(t, dir, "state.yaml", "origins:\n  dev:\n    provider: keys\n    members:\n      billing: { keys: ["+string(pub)+"] }\n")
	keyData, _ := keyset.MarshalPrivateKey(workload)
	keyFile := writeFile(t, dir, "workload.key", string(keyData))
	if _, err := ca.Init(caDir, caTD, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	var logs strings.Builder
	var mu sync.Mutex
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			mu.Lock()
			logs.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	startTestIssuer(t, config, url, "-log-level", "error")
	out := t.TempDir()
	err = runToken(context.Background(), []string{"-issuer", url, "-client-id", "dev/billing", "-key-file", keyFile, "-x509",
		"-key-out", filepath.Join(out, "k"), "-cert-out", filepath.Join(out, "c")})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	os.Stderr = saved
	w.Close()
	<-copied
	mu.Lock()
	defer mu.Unlock()
	got := logs.String()
	if !strings.Contains(got, "issued X.509-SVID") || !strings.Contains(got, "spiffe_id=spiffe://example.org/dev/billing") || !strings.Contains(got, "serial=") {
		t.Errorf("no issuance record at -log-level error:\n%s", got)
	}
	if strings.Contains(got, "level=INFO msg=\"state") || strings.Contains(got, "level=DEBUG") {
		t.Errorf("other lines below the level were written:\n%s", got)
	}
}

// Nothing is asked of the issuer that the files or the bundle would waste.
func TestTokenCommandAsksLastWhatCostsACertificate(t *testing.T) {
	var tokenHits atomic.Int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q,"spiffe_bundle_endpoint":%q,"spiffe_trust_domain":"example.org"}`, srv.URL, srv.URL+"/token", srv.URL+"/bundle")
	})
	bundleUp := true
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, _ *http.Request) {
		if !bundleUp {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		anchor, key := selfSignedAnchor(t)
		b := spiffebundle.New(caTD)
		b.AddX509Authority(anchor)
		if err := b.AddJWTAuthority("k", key.Public()); err != nil {
			t.Error(err)
		}
		body, err := b.Marshal()
		if err != nil {
			t.Error(err)
		}
		w.Write(body)
	})
	mux.HandleFunc("/token", func(http.ResponseWriter, *http.Request) { tokenHits.Add(1) })
	srv = httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	workload, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyData, _ := keyset.MarshalPrivateKey(workload)
	keyFile := writeFile(t, dir, "workload.key", string(keyData))
	base := []string{"-issuer", srv.URL, "-client-id", "dev/billing", "-key-file", keyFile, "-x509"}

	taken := writeFile(t, dir, "taken", "x")
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	p := func(name string) string { return filepath.Join(dir, name) }
	cases := map[string][3]string{
		"an existing key file":        {taken, p("c1"), ""},
		"an existing certificate":     {p("k2"), taken, ""},
		"an existing bundle file":     {p("k3"), p("c3"), taken},
		"a dangling symlink":          {p("dangling"), p("c4"), ""},
		"a missing directory":         {p("nodir/k"), p("c5"), ""},
		"an unwritable directory":     {filepath.Join(locked, "k"), p("c6"), ""},
		"the same path twice":         {p("same"), p("same"), ""},
		"the bundle at the cert path": {p("k7"), p("c7"), p("c7")},
		"a failing bundle fetch":      {p("k8"), p("c8"), ""},
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "an unwritable directory" && os.Geteuid() == 0 {
				t.Skip("root writes anywhere")
			}
			bundleUp = name != "a failing bundle fetch"
			args := append(slices.Clone(base), "-key-out", out[0], "-cert-out", out[1])
			if out[2] != "" {
				args = append(args, "-bundle-out", out[2])
			}
			if err := runToken(context.Background(), args); err == nil {
				t.Error("the command succeeded")
			}
			for _, path := range out {
				if info, err := os.Lstat(path); path != "" && path != taken && err == nil && info.Mode()&os.ModeSymlink == 0 {
					t.Errorf("%s was left behind", path)
				}
			}
		})
	}
	if b, _ := os.ReadFile(taken); string(b) != "x" {
		t.Error("an existing file was changed")
	}
	if n := tokenHits.Load(); n != 0 {
		t.Errorf("%d token requests; a certificate was asked for before it was known it could be kept", n)
	}
}

func selfSignedAnchor(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "anchor"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestTokenCommandX509Flags(t *testing.T) {
	for name, args := range map[string][]string{
		"audience with x509":    {"-issuer", "http://127.0.0.1:1", "-x509", "-audience", "a", "-key-out", "k", "-cert-out", "c"},
		"x509 without outputs":  {"-issuer", "http://127.0.0.1:1", "-x509"},
		"x509 without cert-out": {"-issuer", "http://127.0.0.1:1", "-x509", "-key-out", "k"},
		"outputs without x509":  {"-issuer", "http://127.0.0.1:1", "-audience", "a", "-key-out", "k"},
		"neither kind":          {"-issuer", "http://127.0.0.1:1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runToken(context.Background(), args)
			if _, ok := err.(usageError); !ok {
				t.Errorf("error %v, want a usage error", err)
			}
		})
	}
}
