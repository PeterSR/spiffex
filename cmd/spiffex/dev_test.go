package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/PeterSR/spiffex/internal/agent"
)

// devTokenHelperEnv makes the test binary act as "spiffex dev token", for
// an agent's subject token command. It does not start with SPIFFEX_, so no
// flag reads it.
const devTokenHelperEnv = "DEV_TOKEN_HELPER_ARGS"

func TestDevTokenHelper(t *testing.T) {
	args := os.Getenv(devTokenHelperEnv)
	if args == "" {
		t.Skip("run by TestDevExchange as an agent's subject token command")
	}
	var argv []string
	if err := json.Unmarshal([]byte(args), &argv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := runDev(context.Background(), append([]string{"token"}, argv...)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func quietStdout(t *testing.T) {
	t.Helper()
	stdout := os.Stdout
	os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	t.Cleanup(func() { os.Stdout = stdout })
}

// devMint runs "spiffex dev token" and returns the token it writes.
func devMint(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "subject.jwt")
	if err := runDev(context.Background(), append([]string{"token", "-out", out}, args...)); err != nil {
		return "", err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data)), nil
}

// "spiffex dev -exchange -ca" makes a trust domain whose workloads exchange
// subject tokens that "spiffex dev token" signs, for JWT-SVIDs and
// X.509-SVIDs, with or without an agent.
func TestDevExchange(t *testing.T) {
	quietStdout(t)
	dir := filepath.Join(t.TempDir(), "td")
	url := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	err := runDev(context.Background(), []string{"-dir", dir, "-exchange", "-ca", "-listen", strings.TrimPrefix(url, "http://"),
		"-origin", "tenant={tenant}/{service}", "-origin", "platform={service}"})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, devUpstreamKey)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("upstream key: %v %v", fi, err)
	}
	_, report, err := loadDevState(filepath.Join(dir, "issuer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tenant := report.Origins["tenant"]
	if tenant == nil || tenant.JWT == nil || report.Origins["platform"] == nil {
		t.Fatalf("origins: %v", report.Origins)
	}

	token, err := devMint(t, "-dir", dir, "tenant/acme/backend")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := parsed.Claims(tenant.JWT.JWKS.Keys[0].Key, &claims); err != nil {
		t.Fatalf("the token does not verify against the origin's key: %v", err)
	}
	for k, want := range map[string]any{
		"iss": "https://upstream.spiffex.test", "sub": "tenant/acme/backend", "aud": url + "/origins/tenant",
		"tenant": "acme", "service": "backend",
	} {
		if claims[k] != want {
			t.Errorf("claim %s = %v, want %v", k, claims[k], want)
		}
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 3600 {
		t.Errorf("the token lives %vs, want an hour", exp-iat)
	}

	startTestIssuer(t, filepath.Join(dir, "issuer.yaml"), url)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := agent.Discover(ctx, url, spiffeid.RequireTrustDomainFromString("spiffex.test"), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	subject := filepath.Join(t.TempDir(), "subject.jwt")
	if err := runDev(ctx, []string{"token", "-dir", dir, "-out", subject, "platform/tenant-manager"}); err != nil {
		t.Fatal(err)
	}
	svid, err := client.FetchToken(ctx, agent.SubjectToken{File: subject}, []string{"backend"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := jwtsvid.ParseInsecure(svid.Value, []string{"backend"}); err != nil || got.ID.String() != "spiffe://spiffex.test/platform/tenant-manager" {
		t.Errorf("exchanged for %v, %v", got, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := client.FetchX509SVID(ctx, agent.SubjectToken{File: subject}, key)
	if err != nil || cert.SPIFFEID.String() != "spiffe://spiffex.test/platform/tenant-manager" {
		t.Fatalf("X.509-SVID %v, %v", cert, err)
	}

	// An agent minting a subject token for each request, as the printed
	// instructions say to run one.
	helperArgs, _ := json.Marshal([]string{"-dir", dir, "tenant/acme/backend"})
	t.Setenv(devTokenHelperEnv, string(helperArgs))
	command, _ := json.Marshal([]string{os.Args[0], "-test.run=^TestDevTokenHelper$"})
	socket := filepath.Join(t.TempDir(), "agent.sock")
	agentCtx, stopAgent := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runAgent(agentCtx, []string{"-issuer", url, "-subject-token-command", string(command), "-socket", socket, "-log-level", "error"})
	}()
	t.Cleanup(func() {
		stopAgent()
		if err := <-done; err != nil {
			t.Errorf("the agent stopped with %v", err)
		}
	})
	addr := workloadapi.WithAddr("unix://" + socket)
	var x509svid string
	for deadline := time.Now().Add(10 * time.Second); ; {
		got, err := workloadapi.FetchX509SVID(ctx, addr)
		if err == nil {
			x509svid = got.ID.String()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent gave no X.509-SVID: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if x509svid != "spiffe://spiffex.test/tenant/acme/backend" {
		t.Errorf("the agent's X.509-SVID is for %s", x509svid)
	}
	if got, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "orders"}, addr); err != nil || got.ID.String() != "spiffe://spiffex.test/tenant/acme/backend" {
		t.Errorf("the agent's JWT-SVID: %v, %v", got, err)
	}
}

// "spiffex dev token" follows the state as edited by hand: another prefix,
// an escaped claim name, a required claim it cannot fill alone.
func TestDevTokenFollowsTheState(t *testing.T) {
	quietStdout(t)
	dir := filepath.Join(t.TempDir(), "td")
	if err := runDev(context.Background(), []string{"-dir", dir, "-exchange"}); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.yaml")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	edited := string(data) + `  custom:
    provider: dev
    prefix: /svc/v1
    name: "x/{team~1name}"
    require: [owner]
`
	if err := os.WriteFile(statePath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := devMint(t, "-dir", dir, "svc/v1/x/kitchen"); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("a token without the required claim: %v", err)
	}
	token, err := devMint(t, "-dir", dir, "-claim", "owner=peter", "spiffe://spiffex.test/svc/v1/x/kitchen")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatal(err)
	}
	if claims["team/name"] != "kitchen" || claims["owner"] != "peter" || claims["aud"] != "http://127.0.0.1:8443/origins/svc/v1" {
		t.Errorf("claims %v", claims)
	}
	if token, err := devMint(t, "-dir", dir, "/dev/orders"); err != nil || token == "" {
		t.Errorf("the default origin dev: %v", err)
	}

	for _, args := range [][]string{
		{"-dir", dir, "svc/v1/y/kitchen"},                  // a literal that does not match
		{"-dir", dir, "svc/v1/x"},                          // too short
		{"-dir", dir, "dev/orders/extra"},                  // too long
		{"-dir", dir, "other/orders"},                      // under no origin
		{"-dir", dir, "spiffe://example.org/dev/orders"},   // another trust domain
		{"-dir", dir, "-ttl", "25h", "dev/orders"},         // longer than max_token_lifetime
		{"-dir", dir, "-ttl", "0s", "dev/orders"},          // not positive
		{"-dir", dir, "-claim", "service=x", "dev/orders"}, // set from the path already
		{"-dir", dir, "-claim", "aud=x", "dev/orders"},     // set by dev token
		{"-dir", dir, "-claim", "novalue", "dev/orders"},   // not NAME=VALUE
		{"-dir", dir},                   // no path
		{"-dir", dir, ""},               // an empty path
		{"-dir", dir, "dev/a", "dev/b"}, // two paths
		{"dev/orders"},                  // no -dir
	} {
		if _, err := devMint(t, args...); err == nil {
			t.Errorf("dev token %v succeeded", args)
		}
	}

	// A directory made without -exchange has no upstream.
	keysDir := filepath.Join(t.TempDir(), "keys-td")
	if err := runDev(context.Background(), []string{"-dir", keysDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := devMint(t, "-dir", keysDir, "dev/orders"); err == nil {
		t.Error("dev token minted for a keys origin")
	}
}

// -out replaces the file in one step and keeps it private.
func TestDevTokenReplacesItsOutput(t *testing.T) {
	quietStdout(t)
	dir := filepath.Join(t.TempDir(), "td")
	if err := runDev(context.Background(), []string{"-dir", dir, "-exchange"}); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	out := filepath.Join(outDir, "orders.jwt")
	var tokens []string
	for range 2 {
		if err := runDev(context.Background(), []string{"token", "-dir", dir, "-out", out, "dev/orders"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, string(data))
		if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, %v", fi.Mode(), err)
		}
	}
	if tokens[0] == tokens[1] {
		t.Error("the second token is the first")
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

func TestDevExchangeRefusals(t *testing.T) {
	quietStdout(t)
	base := filepath.Join(t.TempDir(), "td")
	for _, args := range [][]string{
		{"-origin", "a={x}"},                                  // -origin without -exchange
		{"-exchange", "-workloads", "a,b"},                    // -workloads with -exchange
		{"-exchange", "-origin", "a"},                         // no template
		{"-exchange", "-origin", "a="},                        // an empty template
		{"-exchange", "-origin", "A={x}"},                     // bad origin name
		{"-exchange", "-origin", "a={x|hash:24}"},             // an operation
		{"-exchange", "-origin", "a={x/y}"},                   // a nested claim
		{"-exchange", "-origin", "a={sub}"},                   // a claim dev token sets
		{"-exchange", "-origin", "a={x}/{x}"},                 // a claim twice
		{"-exchange", "-origin", "a={x}-y"},                   // not a whole segment
		{"-exchange", "-origin", "a={x}", "-origin", "a={y}"}, // an origin twice
	} {
		if err := runDev(context.Background(), append([]string{"-dir", base}, args...)); err == nil {
			t.Errorf("dev %v succeeded", args)
		}
		if _, err := os.Stat(base); err == nil {
			t.Fatalf("dev %v left a directory behind", args)
		}
	}
}

// TestDevDeepDir checks that spiffex dev makes a trust domain in a directory
// too deep for a Unix socket, and that its walkthrough names a socket an
// agent can listen on.
func TestDevDeepDir(t *testing.T) {
	if socket, note := devSocket("/d", "agent"); socket != "/d/agent.sock" || note != "" {
		t.Errorf("devSocket(/d) = %s, %q", socket, note)
	}
	// A directory short enough for the agent's staging socket, with a name
	// that makes the socket itself too long.
	dir80 := "/" + strings.Repeat("d", 79)
	if socket, _ := devSocket(dir80, "short"); socket != dir80+"/short.sock" {
		t.Errorf("devSocket(%s, short) = %s", dir80, socket)
	}
	for _, name := range []string{"inventory-services1", strings.Repeat("n", 200)} {
		if socket, note := devSocket(dir80, name); len(socket) > 103 || !strings.HasPrefix(socket, "/tmp/") || note == "" {
			t.Errorf("devSocket(%s, %s) = %s, %q", dir80, name, socket, note)
		}
	}
	for _, args := range [][]string{{"-exchange"}, {"-workloads", "orders"}} {
		parent := filepath.Join(t.TempDir(), strings.Repeat("deep", 30))
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(parent, "td")
		out, err := captureStdout(t, func() error { return runDev(context.Background(), append([]string{"-dir", dir}, args...)) })
		if err != nil {
			t.Fatalf("dev %v: %v", args, err)
		}
		name := "agent"
		if args[0] != "-exchange" {
			name = "orders"
		}
		socket, note := devSocket(dir, name)
		if !strings.HasPrefix(socket, "/tmp/") || !strings.Contains(out, "-socket "+socket+"\n") || !strings.Contains(out, note) {
			t.Fatalf("dev %v does not name the socket %s:\n%s", args, socket, out)
		}
		l, err := agent.Listen(socket, 0o600)
		if err != nil {
			t.Fatalf("dev %v names a socket no agent can listen on: %v", args, err)
		}
		l.Close()
	}
}
