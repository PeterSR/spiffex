package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/secretperm"
)

var caTD = spiffeid.RequireTrustDomainFromString("example.org")

func caArgs(dir string) []string {
	return []string{"-dir", dir, "-trust-domain", "example.org", "-activation-delay", "1h", "-x509-svid-ttl", "1h"}
}

func TestCAInitAndList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	out, err := captureStdout(t, func() error {
		return caInit([]string{"-dir", dir, "-trust-domain", "example.org"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "made ca-") {
		t.Errorf("init printed %q", out)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("CA directory: %v %v", info, err)
	}

	out, err = captureStdout(t, func() error { return caList(caArgs(dir)) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".crt", "P-256", "signing", "anchor", "published"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}

	// list and prune refuse to guess the issuer's settings.
	for _, args := range [][]string{
		{"-dir", dir, "-trust-domain", "example.org"},
		{"-dir", dir, "-trust-domain", "example.org", "-activation-delay", "1h"},
		{"-trust-domain", "example.org", "-activation-delay", "1h", "-x509-svid-ttl", "1h"},
		{"-dir", dir, "-activation-delay", "1h", "-x509-svid-ttl", "1h"},
	} {
		if err := caList(args); err == nil {
			t.Errorf("ca list %v guessed", args)
		}
		if err := caPrune(args); err == nil {
			t.Errorf("ca prune %v guessed", args)
		}
	}
	if err := caInit([]string{"-dir", dir}); err == nil {
		t.Error("ca init without a trust domain")
	}
	if err := runCA(context.Background(), []string{"nope"}); err == nil {
		t.Error("an unknown ca command was accepted")
	}
}

func TestCAWithSettingsFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := captureStdout(t, func() error {
		return caInit([]string{"-dir", filepath.Join(dir, "ca"), "-trust-domain", "example.org"})
	}); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "issuer.yaml")
	settings := "issuer: https://issuer.example.org\ntrust_domain: example.org\nkeys_dir: keys\nstate: { file: state.yaml }\nca_dir: ca\n"
	if err := os.WriteFile(config, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return caList([]string{"-config", config}) })
	if err != nil || !strings.Contains(out, "signing") {
		t.Errorf("ca list -config: %v\n%s", err, out)
	}
	if err := caList([]string{"-config", config, "-dir", "elsewhere"}); err == nil {
		t.Error("-config with -dir was accepted")
	}
	if err := os.WriteFile(config, []byte(strings.Replace(settings, "ca_dir: ca\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := caList([]string{"-config", config}); err == nil || !strings.Contains(err.Error(), "ca_dir") {
		t.Errorf("settings without ca_dir: %v", err)
	}
}

// The intermediate flow: a request, signed elsewhere, installed.
func TestCACSRAndImport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	scratch := t.TempDir()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ca.NameConstraints(caTD)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := ca.SubjectKeyID(rootKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski,
		ExtraExtensions: []pkix.Extension{fence},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootsFile := filepath.Join(scratch, "roots.pem")
	if err := os.WriteFile(rootsFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	csrFile := filepath.Join(scratch, "ca.csr")
	out, err := captureStdout(t, func() error {
		return caCSR([]string{"-dir", dir, "-trust-domain", "example.org", "-out", csrFile})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "made ca-") {
		t.Errorf("csr printed %q", out)
	}
	if err := caCSR([]string{"-dir", dir, "-trust-domain", "example.org", "-out", csrFile}); err == nil {
		t.Error("an existing request file was overwritten")
	}
	listed, err := captureStdout(t, func() error { return caList(append(caArgs(dir), "-roots", rootsFile)) })
	if err != nil || strings.Contains(listed, "signing") || !strings.Contains(listed, "waits for its certificate") || !strings.Contains(listed, "anchor") {
		t.Errorf("a directory with only a pending key: %v\n%s", err, listed)
	}

	block, _ := pem.Decode(readFile(t, csrFile))
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("the request: %v", err)
	}
	reqSKI, err := ca.SubjectKeyID(req.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signed := &x509.Certificate{
		SerialNumber: big.NewInt(2), RawSubject: req.RawSubject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: reqSKI,
		ExtraExtensions: []pkix.Extension{fence},
	}
	der, err := x509.CreateCertificate(rand.Reader, signed, root, req.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(scratch, "signed.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without the roots, the chain cannot be checked.
	if err := caImport([]string{"-cert", certFile, "-dir", dir, "-trust-domain", "example.org"}); err == nil {
		t.Error("imported a certificate whose root is not known")
	}
	if _, err := captureStdout(t, func() error {
		return caImport([]string{"-cert", certFile, "-dir", dir, "-trust-domain", "example.org", "-roots", rootsFile})
	}); err != nil {
		t.Fatal(err)
	}
	out, err = captureStdout(t, func() error { return caList(append(caArgs(dir), "-roots", rootsFile)) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "signing") || !strings.Contains(out, "ca_roots") || strings.Contains(out, "waits for its certificate") {
		t.Errorf("list after import:\n%s", out)
	}
	if lines := strings.Count(out, "anchor"); lines != 1 {
		t.Errorf("%d anchors listed, want only the operator's root:\n%s", lines, out)
	}
	if err := caImport([]string{"-dir", dir, "-trust-domain", "example.org", "-roots", rootsFile}); err == nil {
		t.Error("ca import without -cert")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCAPrune(t *testing.T) {
	dir := t.TempDir()
	past := time.Now().Add(-48 * time.Hour)
	var files []string
	for _, at := range []time.Time{past, past.Add(10 * time.Hour)} {
		c, err := ca.Init(dir, caTD, at, 365*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{c.File, c.KeyFile} {
			if err := os.Chtimes(filepath.Join(dir, name), at, at); err != nil {
				t.Fatal(err)
			}
		}
		files = append(files, c.File, c.KeyFile)
	}

	out, err := captureStdout(t, func() error { return caPrune(append(caArgs(dir), "-dry-run")) })
	if err != nil || !strings.Contains(out, "would remove "+files[0]) || strings.Contains(out, files[2]) {
		t.Errorf("dry run: %v\n%s", err, out)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("the dry run removed %s", f)
		}
	}
	out, err = captureStdout(t, func() error { return caPrune(caArgs(dir)) })
	if err != nil || !strings.Contains(out, "removed "+files[0]) {
		t.Errorf("prune: %v\n%s", err, out)
	}
	for i, f := range files {
		_, err := os.Stat(filepath.Join(dir, f))
		if gone := os.IsNotExist(err); gone != (i < 2) {
			t.Errorf("%s: removed = %v", f, gone)
		}
	}
	out, err = captureStdout(t, func() error { return caList(caArgs(dir)) })
	if err != nil || strings.Contains(out, "retired") || !strings.Contains(out, "signing") {
		t.Errorf("list after prune: %v\n%s", err, out)
	}
}

func TestCACSRLeavesNothingBehindOnAFailure(t *testing.T) {
	dir := t.TempDir()
	scratch := t.TempDir()
	// A request file that cannot be made is found out before any key is.
	if err := caCSR([]string{"-dir", dir, "-trust-domain", "example.org", "-out", filepath.Join(scratch, "missing", "ca.csr")}); err == nil {
		t.Fatal("wrote a request into a directory that does not exist")
	}
	existing := filepath.Join(scratch, "ca.csr")
	if err := os.WriteFile(existing, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := caCSR([]string{"-dir", dir, "-trust-domain", "example.org", "-out", existing}); err == nil {
		t.Fatal("overwrote an existing request file")
	}
	if got := readFile(t, existing); string(got) != "keep" {
		t.Errorf("the existing file now holds %q", got)
	}
	if pending, err := ca.Pending(dir); err != nil || len(pending) != 0 {
		t.Errorf("a failed request left keys %v (%v)", pending, err)
	}
	if err := caInit([]string{"-dir", dir, "-trust-domain", "example.org", "-valid-for", "1h"}); err == nil {
		t.Error("a root valid for an hour was made")
	}
}

func TestGuardCAKeys(t *testing.T) {
	user := secretperm.User{UID: uint32(os.Getuid()) + 1000, GID: uint32(os.Getgid()) + 1000}
	dir := t.TempDir()
	c, err := ca.Init(dir, caTD, time.Now().Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opts := ca.Options{Dir: dir, TrustDomain: caTD, ActivationDelay: time.Hour, Retention: ca.Retention(time.Hour)}
	w, err := ca.NewWatcher(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The certificate is public (mode 0644) and not judged; the key is private.
	if err := guardCAKeys(w, dir, user); err != nil {
		t.Fatalf("a private key beside a public certificate: %v", err)
	}

	// A key that becomes readable stops signing; its certificate stays published.
	if err := os.Chmod(filepath.Join(dir, c.KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	w.Reload()
	set, _, _ := w.Current()
	if _, err := set.Select(time.Now(), time.Hour); !errors.Is(err, ca.ErrNoSigningCA) || len(set.Anchors()) != 1 {
		t.Errorf("after the key became readable: %v, %d anchors", err, len(set.Anchors()))
	}

	// And at startup a readable key is refused.
	other, err := ca.NewWatcher(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := guardCAKeys(other, dir, user); err == nil {
		t.Error("a CA key readable by the verifier user was accepted at startup")
	}
}
