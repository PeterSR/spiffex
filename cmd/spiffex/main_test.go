package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeterSR/spiffex/internal/config"
	"github.com/PeterSR/spiffex/internal/keyset"
)

func TestFlagsFromEnvironment(t *testing.T) {
	fs := newFlagSet("x", "")
	fs.SetOutput(io.Discard)
	issuer := fs.String("issuer", "", "")
	socketMode := fs.String("socket-mode", "0600", "")
	t.Setenv("SPIFFEX_ISSUER", "https://from-env")
	t.Setenv("SPIFFEX_SOCKET_MODE", "0660")

	if err := parseFlags(fs, []string{"-socket-mode", "0640"}); err != nil {
		t.Fatal(err)
	}
	if *issuer != "https://from-env" {
		t.Errorf("issuer = %q, want the environment value", *issuer)
	}
	if *socketMode != "0640" {
		t.Errorf("socket-mode = %q, want the command line to win over the environment", *socketMode)
	}
	if err := parseFlags(newFlagSet("y", ""), []string{"stray"}); err == nil {
		t.Error("a stray argument was accepted")
	}
}

// What "spiffex dev" writes is a configuration the issuer accepts, with keys
// the agent can use.
func TestDevCreatesAWorkingTrustDomain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "td")
	stdout := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	err := runDev(context.Background(), []string{"-dir", dir, "-workloads", "orders,billing,shipping"})
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "issuer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Clients) != 3 || cfg.Clients["shipping"].SPIFFEID.String() != "spiffe://spiffex.test/shipping" {
		t.Errorf("clients = %v", cfg.Clients)
	}
	if _, err := keyset.LoadDir(cfg.KeysDir); err != nil {
		t.Error(err)
	}
	for _, w := range []string{"orders", "billing", "shipping"} {
		data, err := os.ReadFile(filepath.Join(dir, "workloads", w+".key"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := keyset.ParsePrivateKey(data); err != nil {
			t.Errorf("%s: %v", w, err)
		}
	}
	if err := runDev(context.Background(), []string{"-dir", dir}); err == nil {
		t.Error("dev overwrote an existing directory")
	}
	for _, args := range [][]string{
		{"-dir", dir + "2", "-listen", ":9000"},
		{"-dir", dir + "2", "-listen", "0.0.0.0:9000"},
		{"-dir", dir + "2", "-workloads", "a,a"},
		{"-dir", dir + "2", "-workloads", "a/b"},
	} {
		if err := runDev(context.Background(), args); err == nil {
			t.Errorf("dev %v succeeded", args)
		}
		if _, err := os.Stat(dir + "2"); err == nil {
			t.Fatalf("dev %v left a directory behind", args)
		}
	}
}

func TestKeyCommands(t *testing.T) {
	dir := t.TempDir()
	stdout := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer func() { os.Stdout = stdout }()

	if err := keyAdd([]string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := keyList([]string{"-dir", dir}); err == nil {
		t.Error("key list ran without knowing the issuer's activation delay and token TTL")
	}
	if err := keyList([]string{"-dir", dir, "-activation-delay", "1h", "-token-ttl", "5m"}); err != nil {
		t.Fatal(err)
	}
	clientKey := filepath.Join(dir, "client.key")
	if err := keyGenerate([]string{"-out", clientKey, "-alg", "RS256"}); err != nil {
		t.Fatal(err)
	}
	if err := keyGenerate([]string{"-out", clientKey}); err == nil {
		t.Error("generate overwrote an existing key")
	}
	if err := keyPublic([]string{"-in", clientKey}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(clientKey); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("client key mode = %v (%v)", info.Mode(), err)
	}
	if err := keyPrune([]string{"-dir", dir, "-activation-delay", time.Hour.String()}); err == nil {
		t.Error("key prune ran without the issuer's token TTL")
	}
	if err := keyPrune([]string{"-dir", dir, "-activation-delay", time.Hour.String(), "-token-ttl", "5m", "-dry-run"}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"frobnicate"}, io.Discard); err == nil {
		t.Error("an unknown command succeeded")
	}
}
