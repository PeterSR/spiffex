package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commonName(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "first")
	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	r.every = 0
	if cn := commonName(t, r); cn != "first" {
		t.Fatalf("serving %s", cn)
	}
	later := time.Now().Add(time.Second)
	writeCert(t, dir, "renewed")
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.Chtimes(filepath.Join(dir, f), later, later); err != nil {
			t.Fatal(err)
		}
	}
	if cn := commonName(t, r); cn != "renewed" {
		t.Errorf("serving %s after renewal, want renewed", cn)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cn := commonName(t, r); cn != "renewed" {
		t.Errorf("a broken certificate file replaced a good one: serving %s", cn)
	}
}
