package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/manage"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// trustDomainDir is a trust domain on disk: the issuer's settings with
// management on, its signing keys, and an operator's key pair. The issuer
// is not running yet; startIssuer runs it.
type trustDomainDir struct {
	dir, config, issuerURL string
	srv                    *httptest.Server
}

func newTrustDomainDir(t *testing.T) *trustDomainDir {
	t.Helper()
	dir := t.TempDir()
	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	d := &trustDomainDir{dir: dir, issuerURL: "http://" + srv.Listener.Addr().String(), srv: srv}
	if err := os.Mkdir(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := keyset.Add(filepath.Join(dir, "keys"), keyset.ES256, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	d.config = writeFile(t, dir, "issuer.yaml", "issuer: "+d.issuerURL+`
trust_domain: example.org
keys_dir: keys
state: { file: state.yaml }
management: true
`)
	for _, name := range []string{"alice", "bob"} {
		signer, err := keyset.Generate(keyset.ES256)
		if err != nil {
			t.Fatal(err)
		}
		if err := writePrivateKey(filepath.Join(dir, name+".key"), signer); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(filepath.Join(dir, name+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		if err := writePublicKey(f, signer.Public()); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	return d
}

func (d *trustDomainDir) path(name string) string { return filepath.Join(d.dir, name) }

// startIssuer runs the issuer with the management API, wired as spiffex
// issuer wires it.
func (d *trustDomainDir) startIssuer(t *testing.T) {
	t.Helper()
	s, err := settings.Load(d.config)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(s.State)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol := policy.New(policy.Options{Settings: s.Validation, Logger: logger})
	if err := pol.Apply(snap); err != nil {
		t.Fatal(err)
	}
	keys, err := keyset.NewWatcher(s.KeysDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manage.New(manage.Config{Settings: s.Validation, Store: st, Keys: keys, Policy: pol, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := issuer.New(issuer.Config{URL: s.Issuer(), TrustDomain: s.TrustDomain(), Keys: keys, Policy: pol, Management: m, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	d.srv.Config.Handler = iss.Handler()
	d.srv.Start()
}

func (d *trustDomainDir) stored(t *testing.T) *state.State {
	t.Helper()
	snap, err := (&store.File{Path: d.path("state.yaml")}).Load(context.Background())
	if err != nil || snap.Problem != nil {
		t.Fatalf("%v %v", err, snap.Problem)
	}
	return snap.State
}

func TestBootstrap(t *testing.T) {
	d := newTrustDomainDir(t)
	out, err := captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "alice", "-key", d.path("alice.pub")})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "grant operators gives read, write, delegate on / to spiffe://example.org/operators/alice") {
		t.Errorf("output:\n%s", out)
	}
	st := d.stored(t)
	if o := st.Origins["operators"]; o == nil || o.Provider != "keys" || o.Members["alice"] == nil {
		t.Errorf("origin operators = %+v", o)
	}
	g := st.Grants["operators"]
	if g == nil || g.Who != "spiffe://example.org/operators/alice" || strings.Join(g.Can, ",") != "read,write,delegate" || strings.Join(g.On, ",") != "/" {
		t.Errorf("grant operators = %+v", g)
	}

	// Once there are grants, the API is the way in, unless forced.
	_, err = captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "bob", "-key", d.path("bob.pub")})
	})
	if err == nil || !strings.Contains(err.Error(), "has grants already (operators)") {
		t.Errorf("a second bootstrap: %v", err)
	}
	_, err = captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-grant", "ci", "-who", "spiffe://example.org/ci/**", "-can", "read, write", "-on", "/ci", "-force"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if g := d.stored(t).Grants["ci"]; g == nil || strings.Join(g.Can, ",") != "read,write" {
		t.Errorf("grant ci = %+v", g)
	}

	// A member or grant that exists is replaced only when asked to.
	_, err = captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "alice", "-key", d.path("bob.pub"), "-force"})
	})
	if err == nil || !strings.Contains(err.Error(), "member alice of origin operators and grant operators already: use -replace") {
		t.Errorf("replacing without -replace: %v", err)
	}
	out, err = captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "alice", "-key", d.path("bob.pub"), "-force", "-replace"})
	})
	if err != nil || !strings.Contains(out, "replaced member alice of origin operators\nreplaced grant operators\n") {
		t.Errorf("replacing with -replace: %v\n%s", err, out)
	}

	// What would be invalid is not written.
	_, err = captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-grant", "bad", "-who", "spiffe://example.org/x", "-on", "nope", "-force"})
	})
	if err == nil || d.stored(t).Grants["bad"] != nil {
		t.Errorf("an invalid grant: %v", err)
	}
	for _, args := range [][]string{
		{"-member", "x"},
		{"-config", d.config},
		{"-config", d.config, "-key", d.path("bob.pub")},
	} {
		if err := runBootstrap(t.Context(), args); err == nil {
			t.Errorf("bootstrap %v succeeded", args)
		}
	}
}

func TestStateCommands(t *testing.T) {
	d := newTrustDomainDir(t)
	if _, err := captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "alice", "-key", d.path("alice.pub")})
	}); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return runState(t.Context(), []string{"export", "-config", d.config, "-format", "json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var exported state.State
	if err := json.Unmarshal([]byte(out), &exported); err != nil || exported.Grants["operators"] == nil {
		t.Fatalf("export: %v\n%s", err, out)
	}

	// Import refuses an invalid document and a stale version.
	invalid := writeFile(t, d.dir, "invalid.yaml", "origins: { a: { provider: keys, prefix: / }, b: { provider: keys } }\n")
	if _, err := captureStdout(t, func() error {
		return runState(t.Context(), []string{"import", "-config", d.config, "-f", invalid, "-force"})
	}); err == nil {
		t.Error("an invalid state was imported")
	}
	exported.Origins["more"] = &state.Origin{Provider: "keys"}
	data, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	next := writeFile(t, d.dir, "next.json", string(data))
	if _, err := captureStdout(t, func() error {
		return runState(t.Context(), []string{"import", "-config", d.config, "-f", next, "-if-version", "stale"})
	}); err == nil || !strings.Contains(err.Error(), `not at version "stale"`) {
		t.Errorf("a stale import: %v", err)
	}
	if _, err := captureStdout(t, func() error { return runState(t.Context(), []string{"import", "-config", d.config, "-f", next}) }); err == nil {
		t.Error("an import with neither -if-version nor -force was made")
	}
	if _, err := captureStdout(t, func() error {
		return runState(t.Context(), []string{"import", "-config", d.config, "-f", next, "-force"})
	}); err != nil {
		t.Error(err)
	}
	if d.stored(t).Origins["more"] == nil {
		t.Error("the imported state was not stored")
	}

	// file to tree and back loses nothing.
	tree, back := d.path("tree"), d.path("back.yaml")
	for _, args := range [][]string{
		{"convert", "-from-file", d.path("state.yaml"), "-to-dir", tree},
		{"convert", "-from-dir", tree, "-to-file", back},
	} {
		if _, err := captureStdout(t, func() error { return runState(t.Context(), args) }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(tree, "origins", "operators", "members", "alice.pub")); err != nil {
		t.Errorf("the tree lacks the member's key file: %v", err)
	}
	original, _ := os.ReadFile(d.path("state.yaml"))
	converted, _ := os.ReadFile(back)
	if string(original) != string(converted) {
		t.Errorf("converted back:\n%s\nwant:\n%s", converted, original)
	}
	if _, err := captureStdout(t, func() error {
		return runState(t.Context(), []string{"convert", "-from-file", d.path("state.yaml"), "-to-dir", tree})
	}); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("converting onto an existing tree: %v", err)
	}
}

func TestManageCommand(t *testing.T) {
	d := newTrustDomainDir(t)
	if _, err := captureStdout(t, func() error {
		return runBootstrap(t.Context(), []string{"-config", d.config, "-member", "alice", "-key", d.path("alice.pub")})
	}); err != nil {
		t.Fatal(err)
	}
	d.startIssuer(t)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	alice := []string{"-issuer", d.issuerURL, "-client-id", "operators/alice", "-key-file", d.path("alice.key")}
	manageAs := func(creds []string, args ...string) (string, error) {
		return captureStdout(t, func() error { return runManage(t.Context(), append(args, creds...)) })
	}

	web := writeFile(t, d.dir, "web.yaml", "provider: keys\nprefix: /web\n")
	out, err := manageAs(alice, "put", "origin", "web", "-f", web)
	if err != nil || !strings.HasPrefix(out, `created origin web, version "`) {
		t.Fatalf("put origin: %v\n%s", err, out)
	}
	out, err = manageAs(alice, "get", "origin", "web")
	if err != nil || !strings.Contains(out, `"prefix": "/web"`) {
		t.Errorf("get origin: %v\n%s", err, out)
	}
	if out, err = manageAs(alice, "put", "member", "web", "bob", "-key", d.path("bob.pub")); err != nil {
		t.Errorf("put member: %v\n%s", err, out)
	}
	bob := []string{"-issuer", d.issuerURL, "-client-id", "web/bob", "-key-file", d.path("bob.key")}
	_, err = manageAs(bob, "put", "origin", "web2", "-f", web)
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") {
		t.Errorf("bob without a grant: %v", err)
	}

	// The reasons for a 422 are printed one per line.
	breaking := writeFile(t, d.dir, "web-writers.yaml", "who: spiffe://example.org/web/*\ncan: [write]\non: [/web]\n")
	if _, err := manageAs(alice, "put", "grant", "web-writers", "-f", breaking); err != nil {
		t.Errorf("a grant that keeps closure: %v", err)
	}
	breaking = writeFile(t, d.dir, "everyone.yaml", "who: spiffe://example.org/web/bob\ncan: [delegate]\non: [/]\n")
	_, err = manageAs(alice, "put", "grant", "web-admin", "-f", breaking)
	if err == nil || !strings.Contains(err.Error(), "422 Unprocessable Entity: the change would make the state invalid\n  grants.web-writers: gives write on /web") {
		t.Errorf("a grant that breaks closure: %v", err)
	}

	out, err = manageAs(alice, "get", "state", "-if-match", "ignored")
	if err != nil || !strings.Contains(out, "web-writers") {
		t.Errorf("get state: %v\n%s", err, out)
	}
	_, err = manageAs(alice, "delete", "grant", "web-writers", "-if-match", "stale")
	if err == nil || !strings.Contains(err.Error(), "412") {
		t.Errorf("delete with a stale version: %v", err)
	}
	proposed := writeFile(t, d.dir, "proposed.yaml", "origins: { a: { provider: keys, prefix: / }, b: { provider: keys } }\n")
	out, err = manageAs(alice, "check", "-f", proposed)
	if err == nil || !strings.Contains(out, "overlaps") {
		t.Errorf("check: %v\n%s", err, out)
	}

	// The same through an agent's Workload API socket.
	sock := startAgent(t, d.issuerURL, "operators/alice", d.path("alice.key"))
	viaSocket := []string{"-issuer", d.issuerURL, "-socket", sock}
	for range 2 {
		if out, err := manageAs(viaSocket, "delete", "member", "web", "bob"); err != nil && !strings.Contains(err.Error(), "404") {
			t.Errorf("delete member through the socket: %v\n%s", err, out)
		}
	}
	if d.stored(t).Origins["web"].Members["bob"] != nil {
		t.Error("the member was not removed")
	}

	for _, args := range [][]string{
		{"get"}, {"get", "origin"}, {"put", "origin", "x"}, {"put", "member", "web", "x"}, {"frobnicate", "origin", "x"}, {"check"},
	} {
		if _, err := manageAs(alice, args...); err == nil {
			t.Errorf("manage %v succeeded", args)
		}
	}
}

func TestManageRefusesImpossibleNames(t *testing.T) {
	for _, args := range [][]string{
		{"delete", "member", "web", ".."}, {"put", "member", "web", ".", "-key", "x"}, {"delete", "member", "..", "x"},
		{"get", "origin", "../state"}, {"get", "grant", "a/b"}, {"delete", "provider", "Upper"},
	} {
		_, err := captureStdout(t, func() error { return runManage(t.Context(), append(args, "-issuer", "https://unreachable.invalid")) })
		if err == nil || !strings.Contains(err.Error(), "cannot be the name of a") {
			t.Errorf("manage %v: %v", args, err)
		}
	}
}

// startAgent runs an agent for a keys member on a Unix socket and returns
// the socket's path.
func startAgent(t *testing.T, issuerURL, clientID, keyFile string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyset.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.Discover(ctx, issuerURL, spiffeid.TrustDomain{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{Issuer: client, Credential: agent.PrivateKeyJWT{ClientID: clientID, Key: key},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	go a.Run(ctx)
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := agent.Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := a.NewServer()
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return sock
}
