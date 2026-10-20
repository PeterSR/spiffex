package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// caIssuerSettings writes settings for an issuer with a CA directory and
// returns the path, the issuer URL and the CA directory.
func caIssuerSettings(t *testing.T) (config, url, caDir string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := keyset.Add(filepath.Join(dir, "keys"), keyset.ES256, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	url = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	config = writeFile(t, dir, "issuer.yaml", "issuer: "+url+"\ntrust_domain: example.org\nkeys_dir: keys\nca_dir: ca\nstate: { file: state.yaml }\n")
	writeFile(t, dir, "state.yaml", "{}\n")
	return config, url, filepath.Join(dir, "ca")
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func bundleX509Keys(t *testing.T, url string) int {
	t.Helper()
	var bundle struct {
		Keys []struct {
			Use string `json:"use"`
		} `json:"keys"`
	}
	getJSON(t, url+"/bundle", &bundle)
	n := 0
	for _, k := range bundle.Keys {
		if k.Use == "x509-svid" {
			n++
		}
	}
	return n
}

// The issuer started with a ca_dir publishes the CA's anchors, announces
// X.509-SVIDs, and picks up a CA added while it runs.
func TestIssuerServesTheCA(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	if _, err := ca.Init(caDir, caTD, time.Now().Add(-48*time.Hour), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runIssuer(ctx, []string{"-config", config, "-listen", strings.TrimPrefix(url, "http://"), "-reload-interval", "100ms"})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the issuer stopped with %v", err)
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the issuer did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	var discovery map[string]any
	getJSON(t, url+"/.well-known/openid-configuration", &discovery)
	if discovery["spiffex_x509_svid_supported"] != true {
		t.Errorf("discovery: %v", discovery)
	}
	if n := bundleX509Keys(t, url); n != 1 {
		t.Errorf("%d X.509 authorities in the bundle, want 1", n)
	}

	// The watcher runs: a second root made now is published at the next reload.
	if _, err := ca.Init(caDir, caTD, time.Now().Add(time.Second), 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for bundleX509Keys(t, url) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("the issuer did not publish the CA added while it runs")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestIssuerRefusesToStartWithABadCA(t *testing.T) {
	config, url, caDir := caIssuerSettings(t)
	args := []string{"-config", config, "-listen", strings.TrimPrefix(url, "http://")}

	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runIssuer(context.Background(), args); err == nil || !strings.Contains(err.Error(), "certificate authority") {
		t.Errorf("an empty ca_dir: %v", err)
	}

	c, err := ca.Init(caDir, caTD, time.Now().Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, c.File), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runIssuer(context.Background(), args); err == nil || !strings.Contains(err.Error(), "certificate authority") {
		t.Errorf("a CA certificate that is not one: %v", err)
	}
}
