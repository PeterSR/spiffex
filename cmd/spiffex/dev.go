package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/state"
)

// devOrigin is the keys origin "spiffex dev" puts the workloads in.
const devOrigin = "dev"

var devSettings = template.Must(template.New("settings").Parse(`# A local trust domain made by "spiffex dev". Not for production: the
# issuer serves plain HTTP and its signing key sits next to this file.
issuer: {{.Issuer}}
trust_domain: {{.TrustDomain}}
keys_dir: keys
token_ttl: 5m
activation_delay: 30m
state:
  file: state.yaml
`))

var devState = template.Must(template.New("state").Parse(`# The issuer's state: who gets which identity. The issuer rereads this file
# while it runs. The origin {{.Origin}} takes workloads that hold a private key; each
# member is one workload, with client id {{.Origin}}/<member>.
origins:
  {{.Origin}}:
    provider: keys
    members:
{{- range .Workloads}}
      {{.Name}}:
        keys:
          - |
{{.PublicKey}}
{{- end}}
`))

func runDev(_ context.Context, args []string) error {
	fs := newFlagSet("dev", "-dir DIR [flags]")
	dir := fs.String("dir", "", "directory to create (required; must not exist)")
	trustDomain := fs.String("trust-domain", "spiffex.test", "trust domain")
	listen := fs.String("listen", "127.0.0.1:8443", "address the issuer will listen on")
	workloads := fs.String("workloads", "orders,billing", "comma-separated workload names")
	alg := fs.String("alg", "ES256", "the issuer's signing algorithm, ES256 or RS256")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	td, err := spiffeid.TrustDomainFromString(*trustDomain)
	if err != nil {
		return fmt.Errorf("-trust-domain: %w", err)
	}
	host, port, err := net.SplitHostPort(*listen)
	if ip := net.ParseIP(host); err != nil || port == "" || host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("-listen %q: want a loopback address with a port, such as 127.0.0.1:8443", *listen)
	}
	issuerURL := "http://" + *listen
	if _, err := issuer.ValidateURL(issuerURL); err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	if *alg != string(keyset.ES256) && *alg != string(keyset.RS256) {
		return fmt.Errorf("-alg %q: want ES256 or RS256", *alg)
	}
	var names []string
	for _, name := range strings.Split(*workloads, ",") {
		if _, err := spiffeid.FromSegments(td, devOrigin, name); err != nil {
			return fmt.Errorf("workload %q: %w", name, err)
		}
		if slices.Contains(names, name) {
			return fmt.Errorf("workload %q is listed twice", name)
		}
		names = append(names, name)
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	*dir = abs
	for _, name := range names {
		if sock := filepath.Join(*dir, name+".sock"); len(sock) > 103 {
			return fmt.Errorf("the agent socket %s would be longer than Unix sockets allow; use a shorter -dir", sock)
		}
	}

	if err := os.Mkdir(*dir, 0o700); err != nil {
		return err
	}
	for _, sub := range []string{"keys", "workloads"} {
		if err := os.Mkdir(filepath.Join(*dir, sub), 0o700); err != nil {
			return err
		}
	}
	if _, err := keyset.Add(filepath.Join(*dir, "keys"), keyset.Algorithm(*alg), time.Now()); err != nil {
		return err
	}

	type workload struct{ Name, ClientID, ID, PublicKey string }
	var ws []workload
	for _, name := range names {
		id, err := spiffeid.FromSegments(td, devOrigin, name)
		if err != nil {
			return fmt.Errorf("workload %q: %w", name, err)
		}
		signer, err := keyset.Generate(keyset.ES256)
		if err != nil {
			return err
		}
		if err := writePrivateKey(filepath.Join(*dir, "workloads", name+".key"), signer); err != nil {
			return err
		}
		var pub strings.Builder
		if err := writePublicKey(&pub, signer.Public()); err != nil {
			return err
		}
		indented := "            " + strings.ReplaceAll(strings.TrimSpace(pub.String()), "\n", "\n            ")
		ws = append(ws, workload{Name: name, ClientID: devOrigin + "/" + name, ID: id.String(), PublicKey: indented})
	}

	if err := writeTemplate(filepath.Join(*dir, "issuer.yaml"), devSettings, map[string]any{"Issuer": issuerURL, "TrustDomain": td.Name()}); err != nil {
		return err
	}
	statePath := filepath.Join(*dir, "state.yaml")
	if err := writeTemplate(statePath, devState, map[string]any{"Origin": devOrigin, "Workloads": ws}); err != nil {
		return err
	}
	if err := checkDevState(statePath, issuerURL, td); err != nil {
		return err
	}

	first, second := ws[0], ws[0]
	if len(ws) > 1 {
		second = ws[1]
	}
	fmt.Printf(`Created a local trust domain %[1]s in %[2]s, for trying spiffex out.
Not for production: the issuer serves plain HTTP and its signing key sits in that directory.

Run the issuer:

  spiffex issuer -config %[2]s/issuer.yaml -listen %[3]s

Run an agent for %[4]s, then point any SPIFFE library at it:

  spiffex agent -issuer %[5]s -client-id %[8]s -key-file %[2]s/workloads/%[4]s.key -socket %[2]s/%[4]s.sock
  export SPIFFE_ENDPOINT_SOCKET=unix://%[2]s/%[4]s.sock

Or fetch a token for %[6]s to call %[4]s with, without an agent:

  spiffex token -issuer %[5]s -client-id %[9]s -key-file %[2]s/workloads/%[6]s.key -audience %[7]s

Workloads are members of the origin %[10]s in %[2]s/state.yaml, which the issuer rereads while it runs.
`, td.Name(), *dir, *listen, first.Name, issuerURL, second.Name, first.ID, first.ClientID, second.ClientID, devOrigin)
	return nil
}

func writeTemplate(path string, tmpl *template.Template, data any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := tmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// checkDevState makes sure the state written is one the issuer accepts.
func checkDevState(path, issuerURL string, td spiffeid.TrustDomain) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	st, err := state.ParseState(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := state.Validate(st, state.DefaultSettings(issuerURL, td)).Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
