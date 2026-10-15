package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func publicKeyPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), &key.PublicKey
}

const registryBase = "issuer: https://issuer.example.org\ntrust_domain: example.org\nkeys_dir: keys\n"

func registryClient(id string) string {
	return "  - client_id: " + id + "\n    spiffe_id: spiffe://example.org/" + id + "\n    public_keys:\n      - file: " + id + ".pub\n"
}

func newTestRegistry(t *testing.T, clients ...string) (*Registry, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	doc := registryBase + "clients:\n"
	for _, c := range clients {
		pub, _ := publicKeyPEM(t)
		writeFile(t, filepath.Join(dir, c+".pub"), pub)
		doc += registryClient(c)
	}
	path := filepath.Join(dir, "issuer.yaml")
	writeFile(t, path, doc)
	var logs bytes.Buffer
	r, err := NewRegistry(path, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r, path, &logs
}

func TestRegistryReload(t *testing.T) {
	r, path, logs := newTestRegistry(t, "billing")
	dir := filepath.Dir(path)

	if changed, err := r.Reload(); changed || err != nil {
		t.Fatalf("unchanged file: changed=%v err=%v", changed, err)
	}

	pub, _ := publicKeyPEM(t)
	writeFile(t, filepath.Join(dir, "orders.pub"), pub)
	writeFile(t, path, registryBase+"clients:\n"+registryClient("billing")+registryClient("orders"))
	if changed, err := r.Reload(); !changed || err != nil {
		t.Fatalf("added client: changed=%v err=%v", changed, err)
	}
	if _, ok := r.Client("orders"); !ok {
		t.Error("added client not served")
	}

	// Replacing a key file is a change, even though the YAML is the same.
	newPub, newKey := publicKeyPEM(t)
	writeFile(t, filepath.Join(dir, "billing.pub"), newPub)
	if changed, err := r.Reload(); !changed || err != nil {
		t.Fatalf("replaced key file: changed=%v err=%v", changed, err)
	}
	if c, _ := r.Client("billing"); !c.PublicKeys[0].(*ecdsa.PublicKey).Equal(newKey) {
		t.Error("the replaced key file was not picked up")
	}

	writeFile(t, path, registryBase+"clients:\n"+registryClient("orders"))
	if _, err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Client("billing"); ok {
		t.Error("removed client still served")
	}
	if !strings.Contains(logs.String(), "client removed") {
		t.Errorf("client removal not logged: %s", logs)
	}
}

func TestRegistryKeepsPreviousOnBadOrRestartOnlyChanges(t *testing.T) {
	r, path, _ := newTestRegistry(t, "billing")
	original, _ := os.ReadFile(path)

	writeFile(t, path, "issuer: [this is not")
	if _, err := r.Reload(); err == nil {
		t.Error("a broken file loaded")
	}
	writeFile(t, path, strings.Replace(string(original), "example.org\n", "other.org\n", 1))
	if _, err := r.Reload(); err == nil {
		t.Error("a trust domain change was applied without a restart")
	}
	if _, ok := r.Client("billing"); !ok {
		t.Error("the previous clients were dropped")
	}
	// Spelling out a default is not a change.
	writeFile(t, path, string(original)+"token_ttl: 5m\n")
	if _, err := r.Reload(); err != nil {
		t.Errorf("an explicit default was refused: %v", err)
	}
}

// A file caught halfway through being written must not replace the
// configuration; check waits for the content to hold still.
func TestRegistryCheckWaitsForStableContent(t *testing.T) {
	r, path, _ := newTestRegistry(t, "billing", "orders")
	original, _ := os.ReadFile(path)
	half := string(original)[:strings.Index(string(original), "  - client_id: orders")]

	writeFile(t, path, half)
	r.check()
	if _, ok := r.Client("orders"); !ok {
		t.Fatal("a half-written file was applied at the first check")
	}
	writeFile(t, path, string(original))
	r.check()
	r.check()
	if _, ok := r.Client("orders"); !ok {
		t.Error("orders is gone after the file was completed")
	}

	writeFile(t, path, half)
	r.check()
	r.check()
	if _, ok := r.Client("orders"); ok {
		t.Error("a deliberate removal was not applied after two checks")
	}
}

// An edit that touches upstreams still applies its client changes; the
// upstream part waits for a restart.
func TestRegistryAppliesClientsAlongsideUpstreamEdits(t *testing.T) {
	r, path, logs := newTestRegistry(t, "billing", "orders")
	upstreams := "upstreams:\n  - name: k\n    issuer: https://cluster.example.org\n    audience: spiffex\n    jwks_file: jwks.json\n    rules:\n      - spiffe_id: spiffe://example.org/{sub}\n"
	writeFile(t, path, registryBase+"clients:\n"+registryClient("billing")+upstreams)
	if _, err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Client("orders"); ok {
		t.Error("the client removal in the same edit was held back")
	}
	if len(r.Config().Upstreams) != 0 {
		t.Error("an upstream change was applied without a restart")
	}
	if !strings.Contains(logs.String(), "upstreams changed") {
		t.Errorf("no warning about the pending upstream change: %s", logs)
	}
}
