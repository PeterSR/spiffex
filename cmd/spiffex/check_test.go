package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	runErr := f()
	os.Stdout = stdout
	w.Close()
	return <-done, runErr
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var issuerFlags = []string{"-issuer", "https://issuer.example.org", "-trust-domain", "example.org"}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	valid := writeFile(t, dir, "state.yaml", "origins:\n  kube: { provider: kubernetes }\n")
	invalid := writeFile(t, dir, "bad.yaml", "origins:\n  a: { provider: keys, prefix: /x }\n  b: { provider: keys, prefix: /x/y }\n")
	broken := writeFile(t, dir, "broken.yaml", "origins: { a: { nope: 1 } }\n")

	out, err := captureStdout(t, func() error { return runCheck(t.Context(), append(issuerFlags, valid)) })
	if err != nil || out != "" {
		t.Errorf("valid state: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return runCheck(t.Context(), append(issuerFlags, invalid)) })
	if err == nil || out != "origins.b: prefix /x/y overlaps prefix /x of origin a\n" {
		t.Errorf("invalid state: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return runCheck(t.Context(), append(issuerFlags, valid, broken)) })
	if err == nil || !strings.Contains(out, broken+": origins.a: missing property 'provider'") {
		t.Errorf("unparsable state: %v\n%s", err, out)
	}

	if err := runCheck(t.Context(), []string{valid}); err == nil {
		t.Error("check ran without an issuer and trust domain")
	}
	if err := runCheck(t.Context(), append(issuerFlags, "-provider", "-origin", valid)); err == nil {
		t.Error("-provider and -origin went together")
	}
}

func TestCheckSingleObjects(t *testing.T) {
	dir := t.TempDir()
	provider := writeFile(t, dir, "verify.yaml", `
proof:
  exec: { command: [/opt/verify, -v], shared: false }
name: "{sub}"
`)
	origin := writeFile(t, dir, "cloud.yaml", "provider: verify\n")

	out, err := captureStdout(t, func() error { return runCheck(t.Context(), append(issuerFlags, "-provider", provider)) })
	if err == nil || !strings.Contains(out, "providers.verify.proof.exec.command: ") || !strings.Contains(out, "skipped: ") {
		t.Errorf("provider without the verifier installed: %v\n%s", err, out)
	}

	settings := writeFile(t, dir, "settings.yaml", `
issuer: https://issuer.example.org
trust_domain: example.org
keys_dir: /keys
verifiers:
  - [/opt/verify, -v]
`)
	out, err = captureStdout(t, func() error {
		return runCheck(t.Context(), []string{"-settings", settings, "-origin", origin, provider})
	})
	if err != nil || !strings.HasPrefix(out, "skipped: prefix overlap") {
		t.Errorf("origin with its provider: %v\n%s", err, out)
	}
}

func TestProviderCommands(t *testing.T) {
	out, err := captureStdout(t, func() error { return runProvider(t.Context(), []string{"list"}) })
	if err != nil || !strings.Contains(out, "kubernetes  Pods in the cluster") {
		t.Errorf("list: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return runProvider(t.Context(), []string{"show", "kubernetes"}) })
	want, _ := os.ReadFile("../../providers/kubernetes.yaml")
	if err != nil || out != string(want) {
		t.Errorf("show: %v\n%s", err, out)
	}
	if err := runProvider(t.Context(), []string{"show", "nope"}); err == nil {
		t.Error("showed a provider that does not exist")
	}
	if err := runProvider(t.Context(), []string{"frob"}); err == nil {
		t.Error("an unknown provider command succeeded")
	}
}

func TestExplainCommand(t *testing.T) {
	dir := t.TempDir()
	st := writeFile(t, dir, "state.yaml", "origins:\n  kube: { provider: kubernetes }\n")
	// Signed by nobody in particular: explain never verifies signatures.
	token := writeFile(t, dir, "token", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImF1ZCI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUub3JnL29yaWdpbnMva3ViZSJ9.c2ln\n")
	out, err := captureStdout(t, func() error {
		return runExplain(t.Context(), append(issuerFlags, "-state", st, "-token", token))
	})
	if err == nil || !strings.Contains(out, "origin:    kube") || !strings.Contains(out, "no exp claim") {
		t.Errorf("explain: %v\n%s", err, out)
	}
	if err := runExplain(t.Context(), append(issuerFlags, "-state", st)); err == nil {
		t.Error("explain ran without a token")
	}
}

// check reads the bearer token paths of the settings as the issuer does.
func TestCheckBearerTokenPaths(t *testing.T) {
	dir := t.TempDir()
	settings := writeFile(t, dir, "settings.yaml", `
issuer: https://issuer.example.org
trust_domain: example.org
bearer_token_files:
  - { path: /etc/token, hosts: [idp.example], paths: [/keys] }
`)
	st := writeFile(t, dir, "state.yaml", `
providers:
  p: { proof: { jwt: { issuer: https://idp.example, jwks_uri: "https://idp.example/admin", bearer_token_file: /etc/token, shared: false } }, name: "{sub}" }
origins:
  a: { provider: p }
`)
	out, err := captureStdout(t, func() error { return runCheck(t.Context(), []string{"-settings", settings, st}) })
	if err == nil || !strings.Contains(out, "on /admin") {
		t.Errorf("check: %v\n%s", err, out)
	}
}
