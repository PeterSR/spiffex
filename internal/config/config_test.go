package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func publicPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func indent(s string) string {
	return "          " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n          ")
}

func TestParse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "orders.pub"), []byte(publicPEM(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := `
issuer: https://issuer.example.org
trust_domain: example.org
keys_dir: keys
token_ttl: 2m
activation_delay: 1h
clients:
  - client_id: billing
    spiffe_id: spiffe://example.org/billing
    public_keys:
      - pem: |
` + indent(publicPEM(t)) + `
    audiences: [orders]
  - client_id: orders
    spiffe_id: spiffe://example.org/orders
    public_keys:
      - file: orders.pub
`
	cfg, err := Parse([]byte(doc), dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrustDomain.Name() != "example.org" || cfg.KeysDir != filepath.Join(dir, "keys") {
		t.Errorf("trust domain %s, keys dir %s", cfg.TrustDomain, cfg.KeysDir)
	}
	if cfg.TokenTTL != 2*time.Minute || cfg.ActivationDelay != time.Hour {
		t.Errorf("durations: token_ttl %s, activation_delay %s", cfg.TokenTTL, cfg.ActivationDelay)
	}
	billing, ok := cfg.Clients["billing"]
	if !ok || billing.SPIFFEID.String() != "spiffe://example.org/billing" || len(billing.PublicKeys) != 1 {
		t.Errorf("billing = %+v", billing)
	}
	if len(billing.Audiences) != 1 || billing.Audiences[0] != "orders" {
		t.Errorf("billing audiences = %v", billing.Audiences)
	}
	if _, ok := cfg.Clients["orders"]; !ok {
		t.Error("orders client missing")
	}
}

func TestParseErrors(t *testing.T) {
	key := indent(publicPEM(t))
	base := "issuer: https://issuer.example.org\ntrust_domain: example.org\nkeys_dir: keys\n"
	client := func(id, spiffeID string) string {
		return "  - client_id: " + id + "\n    spiffe_id: " + spiffeID + "\n    public_keys:\n      - pem: |\n" + key + "\n"
	}
	cases := map[string]string{
		"unknown field":         base + "colour: blue\n",
		"missing issuer":        "trust_domain: example.org\nkeys_dir: keys\n",
		"bad trust domain":      "issuer: https://i\ntrust_domain: Example.org\nkeys_dir: keys\n",
		"missing keys_dir":      "issuer: https://i\ntrust_domain: example.org\n",
		"foreign trust domain":  base + "clients:\n" + client("a", "spiffe://other.org/a"),
		"duplicate client":      base + "clients:\n" + client("a", "spiffe://example.org/a") + client("a", "spiffe://example.org/b"),
		"missing client_id":     base + "clients:\n" + client(`""`, "spiffe://example.org/a"),
		"no public keys":        base + "clients:\n  - client_id: a\n    spiffe_id: spiffe://example.org/a\n",
		"missing key file":      base + "clients:\n  - client_id: a\n    spiffe_id: spiffe://example.org/a\n    public_keys:\n      - file: nope.pub\n",
		"private key given":     base + "clients:\n  - client_id: a\n    spiffe_id: spiffe://example.org/a\n    public_keys:\n      - pem: \"-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----\\n\"\n",
		"empty audience":        base + "clients:\n" + client("a", "spiffe://example.org/a") + "    audiences: [\"\"]\n",
		"empty document":        "",
		"two documents":         base + "---\n" + base,
		"key shared by clients": base + "clients:\n" + client("a", "spiffe://example.org/a") + client("b", "spiffe://example.org/b"),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc), t.TempDir()); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
