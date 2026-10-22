package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
	"github.com/PeterSR/spiffex/internal/settings"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// devOrigin is the keys origin "spiffex dev" puts the workloads in, and the
// origin of "spiffex dev -exchange" when no -origin is given.
const devOrigin = "dev"

// devProvider is the provider "spiffex dev -exchange" writes for its
// upstream, and devUpstreamKey the file of the upstream's signing key.
const (
	devProvider    = "dev"
	devUpstreamKey = "upstream.key"
)

// devReservedClaims are the claims "spiffex dev token" sets itself, which a
// name template or -claim cannot fill.
var devReservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti"}

// devUpstreamIssuer is the iss of the subject tokens "spiffex dev token"
// signs. It is never the issuer URL, which the issuer does not accept as a
// subject token's iss, and nothing ever fetches from it.
func devUpstreamIssuer(td spiffeid.TrustDomain) string {
	return "https://upstream." + td.Name()
}

var devSettings = template.Must(template.New("settings").Parse(`# A local trust domain made by "spiffex dev". Not for production: the
# issuer serves plain HTTP and its signing key sits next to this file.
issuer: {{.Issuer}}
trust_domain: {{.TrustDomain}}
keys_dir: keys
{{- if .CA}}
ca_dir: ca
{{- end}}
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

var devExchangeState = template.Must(template.New("state").Parse(`# The issuer's state: who gets which identity. The issuer rereads this file
# while it runs. Workloads exchange subject tokens from a local upstream that
# stands in for a cluster's token issuer: "spiffex dev token" signs them with
# upstream.key, whose public key is below. An origin names a workload by the
# claims of its token, so any path its name template fits is a workload.
providers:
  {{.Provider}}:
    description: the local upstream of "spiffex dev token"
    proof:
      jwt:
        issuer: {{.UpstreamIssuer}}
        jwks: {{.JWKS}}
        shared: false
        max_token_lifetime: 24h
origins:
{{- range .Origins}}
  {{.Name}}:
    provider: {{$.Provider}}
    name: {{.Quoted}}
{{- end}}
`))

// devExchangeOrigin is an origin given to "spiffex dev -exchange" as
// NAME=TEMPLATE.
type devExchangeOrigin struct {
	Name, Template string
	parsed         state.Template
}

// Quoted is the template as a YAML string.
func (o devExchangeOrigin) Quoted() string {
	q, _ := json.Marshal(o.Template)
	return string(q)
}

// example is a path the origin issues, its placeholders filled in.
func (o devExchangeOrigin) example() string {
	segs := []string{o.Name}
	for _, p := range o.parsed {
		if p.Placeholder != "" {
			v := "example-" + p.Placeholder
			if !state.ValidSegment(v) {
				v = "example" // the placeholder's name is too long to add to
			}
			segs = append(segs, v)
		} else {
			segs = append(segs, p.Literal)
		}
	}
	return strings.Join(segs, "/")
}

// parseDevExchangeOrigin reads NAME=TEMPLATE. The template's placeholders
// must be claims "spiffex dev token" can fill from a path: top-level claims
// it does not set itself, each once, without operations. Templates beyond
// that are written into state.yaml by hand.
func parseDevExchangeOrigin(s string) (devExchangeOrigin, error) {
	name, tmpl, ok := strings.Cut(s, "=")
	if !ok {
		return devExchangeOrigin{}, fmt.Errorf("-origin %q: want NAME=TEMPLATE, such as tenant={tenant}/{service}", s)
	}
	if !state.ValidName(name) {
		return devExchangeOrigin{}, fmt.Errorf("-origin %q: the origin name must be 1 to 63 characters from a-z, 0-9 and -, starting with a letter", s)
	}
	if tmpl == "" {
		return devExchangeOrigin{}, fmt.Errorf("-origin %q: the template is empty, which would make the origin one workload; write such an origin into state.yaml instead", s)
	}
	parsed, err := state.ParseTemplate(tmpl, state.KindJWT)
	if err != nil {
		return devExchangeOrigin{}, fmt.Errorf("-origin %q: %w", s, err)
	}
	var seen []string
	for _, p := range parsed {
		switch {
		case p.Placeholder == "":
			continue
		case len(p.Ops) > 0:
			return devExchangeOrigin{}, fmt.Errorf("-origin %q: {%s} has operations, which spiffex dev token cannot reverse; write the origin into state.yaml instead", s, p.Placeholder)
		case !state.ValidSegment(p.Placeholder):
			return devExchangeOrigin{}, fmt.Errorf("-origin %q: {%s} is not a plain claim name of A-Z, a-z, 0-9, ., _ and -", s, p.Placeholder)
		case slices.Contains(devReservedClaims, p.Placeholder):
			return devExchangeOrigin{}, fmt.Errorf("-origin %q: spiffex dev token sets the claim %s itself", s, p.Placeholder)
		case slices.Contains(seen, p.Placeholder):
			return devExchangeOrigin{}, fmt.Errorf("-origin %q: {%s} appears twice", s, p.Placeholder)
		}
		seen = append(seen, p.Placeholder)
	}
	return devExchangeOrigin{Name: name, Template: tmpl, parsed: parsed}, nil
}

func runDev(_ context.Context, args []string) (err error) {
	if len(args) > 0 && args[0] == "token" {
		return devToken(args[1:])
	}
	fs := newFlagSet("dev", "-dir DIR [flags]\n       spiffex dev token -dir DIR [flags] PATH   (run spiffex dev token -h)")
	dir := fs.String("dir", "", "directory to create (required; must not exist)")
	trustDomain := fs.String("trust-domain", "spiffex.test", "trust domain")
	listen := fs.String("listen", "127.0.0.1:8443", "address the issuer will listen on")
	workloads := fs.String("workloads", "orders,billing", "comma-separated workload names, members of the keys origin dev (not with -exchange)")
	alg := fs.String("alg", "ES256", "the issuer's signing algorithm, ES256 or RS256")
	withCA := fs.Bool("ca", false, "also make a root certificate authority, so that the issuer issues X.509-SVIDs")
	exchange := fs.Bool("exchange", false, "have workloads exchange subject tokens from a local upstream, which spiffex dev token signs, instead of holding keys")
	var originFlags stringList
	fs.Var(&originFlags, "origin", "with -exchange: an origin NAME=TEMPLATE whose name template takes claims of the subject token, such as tenant={tenant}/{service} (repeat for several; default dev={service})")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError{errors.New("-dir is required")}
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
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var names []string
	var origins []devExchangeOrigin
	if *exchange {
		if given["workloads"] {
			return usageError{errors.New("-workloads does not go with -exchange: a workload is any path an origin's template fits")}
		}
		if len(originFlags) == 0 {
			originFlags = stringList{devOrigin + "={service}"}
		}
		for _, f := range originFlags {
			o, err := parseDevExchangeOrigin(f)
			if err != nil {
				return usageError{err}
			}
			if slices.ContainsFunc(origins, func(p devExchangeOrigin) bool { return p.Name == o.Name }) {
				return usageError{fmt.Errorf("-origin %s is given twice", o.Name)}
			}
			origins = append(origins, o)
		}
	} else {
		if len(originFlags) > 0 {
			return usageError{errors.New("-origin goes only with -exchange")}
		}
		for _, name := range strings.Split(*workloads, ",") {
			if _, err := spiffeid.FromSegments(td, devOrigin, name); err != nil {
				return fmt.Errorf("workload %q: %w", name, err)
			}
			if slices.Contains(names, name) {
				return fmt.Errorf("workload %q is listed twice", name)
			}
			names = append(names, name)
		}
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	*dir = abs

	if err := os.Mkdir(*dir, 0o700); err != nil {
		return err
	}
	// The directory is new, so whatever fails from here on leaves nothing
	// half made behind.
	defer func() {
		if err != nil {
			_ = os.RemoveAll(*dir)
		}
	}()
	if err := os.Mkdir(filepath.Join(*dir, "keys"), 0o700); err != nil {
		return err
	}
	if _, err := keyset.Add(filepath.Join(*dir, "keys"), keyset.Algorithm(*alg), time.Now()); err != nil {
		return err
	}
	if *withCA {
		if _, err := ca.Init(filepath.Join(*dir, "ca"), td, time.Now(), ca.DefaultRootLifetime); err != nil {
			return err
		}
	}
	settingsPath := filepath.Join(*dir, "issuer.yaml")
	if err := writeTemplate(settingsPath, devSettings, map[string]any{"Issuer": issuerURL, "TrustDomain": td.Name(), "CA": *withCA}); err != nil {
		return err
	}
	if *exchange {
		return devExchangeSetup(*dir, *listen, issuerURL, td, origins, *withCA)
	}

	if err := os.Mkdir(filepath.Join(*dir, "workloads"), 0o700); err != nil {
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

	statePath := filepath.Join(*dir, "state.yaml")
	if err := writeTemplate(statePath, devState, map[string]any{"Origin": devOrigin, "Workloads": ws}); err != nil {
		return err
	}
	if err := checkDevState(settingsPath); err != nil {
		return err
	}

	first, second := ws[0], ws[0]
	if len(ws) > 1 {
		second = ws[1]
	}
	socket, socketNote := devSocket(*dir, first.Name)
	fmt.Printf(`Created a local trust domain %[1]s in %[2]s, for trying spiffex out.
Not for production: the issuer serves plain HTTP and its signing key sits in that directory.

Run the issuer:

  spiffex issuer -config %[2]s/issuer.yaml -listen %[3]s

Run an agent for %[4]s, then point any SPIFFE library at it:

  spiffex agent -issuer %[5]s -client-id %[8]s -key-file %[2]s/workloads/%[4]s.key -socket %[11]s
  export SPIFFE_ENDPOINT_SOCKET=unix://%[11]s
%[12]s
Or fetch a token for %[6]s to call %[4]s with, without an agent:

  spiffex token -issuer %[5]s -client-id %[9]s -key-file %[2]s/workloads/%[6]s.key -audience %[7]s

Workloads are members of the origin %[10]s in %[2]s/state.yaml, which the issuer rereads while it runs.
`, td.Name(), *dir, *listen, first.Name, issuerURL, second.Name, first.ID, first.ClientID, second.ClientID, devOrigin, socket, socketNote)
	if *withCA {
		fmt.Printf(`
The issuer also issues X.509-SVIDs, from the root CA in %[1]s/ca. The agent serves them, or write one to files:

  spiffex token -issuer %[2]s -client-id %[3]s -key-file %[1]s/workloads/%[4]s.key -x509 -key-out %[1]s/%[4]s-svid.key -cert-out %[1]s/%[4]s-svid.crt -bundle-out %[1]s/bundle.crt
`, *dir, issuerURL, first.ClientID, first.Name)
	}
	return nil
}

// devExchangeSetup writes the upstream and the state of "spiffex dev
// -exchange" into dir, which holds the issuer's settings already.
func devExchangeSetup(dir, listen, issuerURL string, td spiffeid.TrustDomain, origins []devExchangeOrigin, withCA bool) error {
	upstream, err := keyset.Generate(keyset.ES256)
	if err != nil {
		return err
	}
	if err := writePrivateKey(filepath.Join(dir, devUpstreamKey), upstream); err != nil {
		return err
	}
	kid, err := keyset.Thumbprint(upstream.Public())
	if err != nil {
		return err
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: upstream.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}}})
	if err != nil {
		return err
	}
	if err := writeTemplate(filepath.Join(dir, "state.yaml"), devExchangeState, map[string]any{
		"Provider":       devProvider,
		"UpstreamIssuer": devUpstreamIssuer(td),
		"JWKS":           string(jwks),
		"Origins":        origins,
	}); err != nil {
		return err
	}
	if err := checkDevState(filepath.Join(dir, "issuer.yaml")); err != nil {
		return err
	}

	example := origins[0].example()
	// The agent splits its subject token command at white space, unless it
	// is a JSON array. It is printed in single quotes for the shell.
	command := "spiffex dev token -dir " + dir + " " + example
	if strings.ContainsFunc(dir, unicode.IsSpace) {
		words, _ := json.Marshal([]string{"spiffex", "dev", "token", "-dir", dir, example})
		command = string(words)
	}
	command = strings.ReplaceAll(command, "'", `'\''`)
	socket, socketNote := devSocket(dir, "agent")
	fmt.Printf(`Created a local trust domain %[1]s in %[2]s, for trying spiffex out.
Not for production: the issuer serves plain HTTP and its signing key sits in that directory.
Workloads prove who they are with subject tokens, as pods do with service account tokens:
spiffex dev token signs them with %[2]s/%[6]s, a local stand-in for a cluster's token issuer.

Run the issuer:

  spiffex issuer -config %[2]s/issuer.yaml -listen %[3]s

Run an agent for %[4]s, which mints a subject token for each request, then point any SPIFFE library at it:

  spiffex agent -issuer %[5]s -subject-token-command '%[7]s' -socket %[8]s
  export SPIFFE_ENDPOINT_SOCKET=unix://%[8]s
%[9]s
Or write a subject token to a file and exchange it for a JWT-SVID, without an agent:

  spiffex dev token -dir %[2]s -out %[2]s/subject.jwt %[4]s
  spiffex token -issuer %[5]s -subject-token-file %[2]s/subject.jwt -audience orders
`, td.Name(), dir, listen, example, issuerURL, devUpstreamKey, command, socket, socketNote)
	if withCA {
		fmt.Printf(`
The issuer also issues X.509-SVIDs, from the root CA in %[1]s/ca. The agent serves them, or write one to files:

  spiffex token -issuer %[2]s -subject-token-file %[1]s/subject.jwt -x509 -key-out %[1]s/svid.key -cert-out %[1]s/svid.crt -bundle-out %[1]s/bundle.crt
`, dir, issuerURL)
	}
	fmt.Printf("\nThe origins are in %s/state.yaml, which the issuer rereads while it runs:\n\n", dir)
	for _, o := range origins {
		fmt.Printf("  spiffe://%s/%s/%s\n", td.Name(), o.Name, o.Template)
	}
	fmt.Println("\nA workload is any path an origin's template fits, with nothing to add to the state.")
	return nil
}

// devSocket returns the socket that the walkthrough of spiffex dev names
// for an agent, NAME.sock in dir. spiffex dev never binds it, so a dir too
// deep for a Unix socket is no reason to refuse; the walkthrough names a
// socket in /tmp instead, with a note on why. The note is empty or ends in
// a newline.
func devSocket(dir, name string) (socket, note string) {
	socket = filepath.Join(dir, name+".sock")
	// The agent creates the socket in a private directory of up to 13
	// bytes, .sx and a number, beside it and moves it into place.
	if len(socket) <= 103 && len(filepath.Dir(socket))+len("/.sx4294967295/s") <= 103 {
		return socket, ""
	}
	// The name is left out, so the socket's length is fixed whatever it is.
	sum := sha256.Sum256([]byte(socket))
	short := filepath.Join("/tmp", "spiffex-"+hex.EncodeToString(sum[:8])+".sock")
	return short, fmt.Sprintf("  (A socket in %s would be too long for a Unix socket, so this one is in /tmp.)\n", dir)
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

// checkDevState makes sure the state written is one the issuer accepts,
// with the settings written next to it.
func checkDevState(settingsPath string) error {
	_, _, err := loadDevState(settingsPath)
	return err
}

// loadDevState reads the settings of a directory made by "spiffex dev" and
// its state, and validates the state as the issuer would.
func loadDevState(settingsPath string) (*settings.Settings, *state.Report, error) {
	s, err := settings.Load(settingsPath)
	if err != nil {
		return nil, nil, err
	}
	if s.State.File == "" {
		return nil, nil, fmt.Errorf("%s: the state is not in a file", settingsPath)
	}
	snap, err := (&store.File{Path: s.State.File}).Load(context.Background())
	if err != nil {
		return nil, nil, err
	}
	if snap.Problem != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.State.File, snap.Problem)
	}
	report := state.Validate(snap.State, s.Validation)
	if err := report.Err(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.State.File, err)
	}
	return s, report, nil
}

func devToken(args []string) error {
	fs := newFlagSet("dev token", `-dir DIR [flags] PATH

Sign a subject token for the workload PATH, such as tenant/acme/backend or a
full spiffe:// ID, as the local upstream of a directory made by
spiffex dev -exchange. The claims come from the name template of the origin
PATH is under; the issuer exchanges the token for that identity.`)
	dir := fs.String("dir", "", "a directory made by spiffex dev -exchange (required)")
	ttl := fs.Duration("ttl", time.Hour, "how long the token lives, at most the origin's max_token_lifetime")
	out := fs.String("out", "", "file to write the token to, replacing it in one step (mode 0600); without it the token is printed")
	var extra stringList
	fs.Var(&extra, "claim", "an extra string claim NAME=VALUE, for an origin edited to require more (repeat for several)")
	rest, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	switch {
	case *dir == "":
		return usageError{errors.New("-dir is required")}
	case len(rest) != 1 || rest[0] == "":
		return usageError{errors.New("give one workload path")}
	case *ttl <= 0:
		return usageError{fmt.Errorf("-ttl %s: want a positive duration", *ttl)}
	}
	s, report, err := loadDevState(filepath.Join(*dir, "issuer.yaml"))
	if err != nil {
		return err
	}
	td := s.TrustDomain()
	id, err := parseDevPath(rest[0], td)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(*dir, devUpstreamKey))
	if err != nil {
		return fmt.Errorf("%w (is %s a directory made by spiffex dev -exchange?)", err, *dir)
	}
	key, err := keyset.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("%s: %w", devUpstreamKey, err)
	}
	if k, ok := key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		return fmt.Errorf("%s: want a P-256 key", devUpstreamKey)
	}
	kid, err := keyset.Thumbprint(key.Public())
	if err != nil {
		return err
	}

	var origin *state.Expanded
	var mintable []string
	// Prefixes do not overlap, so at most one origin can match.
	for _, name := range slices.Sorted(maps.Keys(report.Origins)) {
		e := report.Origins[name]
		if !devTrusts(e, td, kid) {
			continue
		}
		mintable = append(mintable, name)
		if e.Prefix == "/" || id.Path() == e.Prefix || strings.HasPrefix(id.Path(), e.Prefix+"/") {
			origin = e
			break
		}
	}
	if origin == nil {
		if len(mintable) == 0 {
			return fmt.Errorf("no origin in %s takes tokens from %s", s.State.File, devUpstreamKey)
		}
		return fmt.Errorf("%s is under none of the origins that take tokens from %s: %s", id, devUpstreamKey, strings.Join(mintable, ", "))
	}
	if *ttl > origin.JWT.MaxTokenLifetime {
		return fmt.Errorf("-ttl %s: origin %s takes tokens that live at most %s", *ttl, origin.Name, origin.JWT.MaxTokenLifetime)
	}

	claims, err := devTemplateClaims(origin, id)
	if err != nil {
		return err
	}
	for _, c := range extra {
		name, value, ok := strings.Cut(c, "=")
		switch {
		case !ok || name == "":
			return usageError{fmt.Errorf("-claim %q: want NAME=VALUE", c)}
		case slices.Contains(devReservedClaims, name):
			return usageError{fmt.Errorf("-claim %q: spiffex dev token sets %s itself", c, name)}
		}
		if _, ok := claims[name]; ok {
			return usageError{fmt.Errorf("-claim %q: the claim %s is set already", c, name)}
		}
		claims[name] = value
	}
	now := time.Now()
	claims["iss"] = origin.JWT.Issuer
	claims["sub"] = strings.TrimPrefix(id.Path(), "/")
	claims["aud"] = origin.JWT.Audience
	claims["iat"] = jwt.NewNumericDate(now)
	claims["nbf"] = jwt.NewNumericDate(now)
	claims["exp"] = jwt.NewNumericDate(now.Add(*ttl))
	claims["jti"] = rand.Text()

	// The origin decides, as the issuer will: it may have been edited to
	// require more, or to name the claims differently.
	payload, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	decoded, err := state.DecodeClaims(payload)
	if err != nil {
		return err
	}
	got, err := origin.Admit(td, decoded)
	var refused *state.RefusedError
	switch {
	case errors.As(err, &refused):
		return fmt.Errorf("origin %s would not admit the token: %s", origin.Name, refused.LogDetail())
	case err != nil:
		return err
	case got != id:
		return fmt.Errorf("origin %s would name the token %s, not %s", origin.Name, got, id)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return err
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(token)
		return nil
	}
	return replaceFile(*out, []byte(token+"\n"))
}

// parseDevPath reads a workload path, with or without its leading /, or a
// full SPIFFE ID of the trust domain.
func parseDevPath(s string, td spiffeid.TrustDomain) (spiffeid.ID, error) {
	if strings.HasPrefix(s, "spiffe://") {
		id, err := spiffeid.FromString(s)
		if err != nil {
			return spiffeid.ID{}, err
		}
		if id.TrustDomain() != td {
			return spiffeid.ID{}, fmt.Errorf("%s is not in the trust domain %s", id, td.Name())
		}
		return id, nil
	}
	id, err := spiffeid.FromPath(td, "/"+strings.TrimPrefix(s, "/"))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("workload %q: %w", s, err)
	}
	return id, nil
}

// devTrusts reports whether an origin takes the tokens of the local
// upstream: its iss, and its key, the one whose thumbprint is kid.
func devTrusts(e *state.Expanded, td spiffeid.TrustDomain, kid string) bool {
	if e.JWT == nil || e.JWT.Issuer != devUpstreamIssuer(td) || e.JWT.JWKS == nil {
		return false
	}
	for _, k := range e.JWT.JWKS.Keys {
		if t, err := keyset.Thumbprint(k.Key); err == nil && t == kid {
			return true
		}
	}
	return false
}

// devIDShape is the path of an origin's identities, prefix and template,
// as /tenant/{tenant}/{service}.
func devIDShape(e *state.Expanded) string {
	switch {
	case len(e.Template) == 0:
		return e.Prefix
	case e.Prefix == "/":
		return "/" + e.Template.String()
	}
	return e.Prefix + "/" + e.Template.String()
}

// devTemplateClaims reverses the origin's name template: it returns the
// claims that make the template name id.
func devTemplateClaims(e *state.Expanded, id spiffeid.ID) (map[string]any, error) {
	rest := strings.TrimPrefix(strings.TrimPrefix(id.Path(), strings.TrimSuffix(e.Prefix, "/")), "/")
	var segs []string
	if rest != "" {
		segs = strings.Split(rest, "/")
	}
	if len(segs) != len(e.Template) {
		return nil, fmt.Errorf("origin %s names its workloads %s, which %s does not fit", e.Name, devIDShape(e), id)
	}
	claims := map[string]any{}
	for i, p := range e.Template {
		if p.Placeholder == "" {
			if segs[i] != p.Literal {
				return nil, fmt.Errorf("origin %s names its workloads %s, which %s does not fit", e.Name, devIDShape(e), id)
			}
			continue
		}
		if len(p.Ops) > 0 || strings.Contains(p.Placeholder, "/") {
			return nil, fmt.Errorf("origin %s: spiffex dev token cannot fill {%s}, which has operations or names a nested claim; give its claims with -claim and sign another way", e.Name, p.Placeholder)
		}
		// A top-level claim, its name escaped as in a JSON Pointer.
		name := strings.NewReplacer("~1", "/", "~0", "~").Replace(p.Placeholder)
		if slices.Contains(devReservedClaims, name) {
			return nil, fmt.Errorf("origin %s: spiffex dev token sets the claim %s itself, so it cannot fill {%s}", e.Name, name, p.Placeholder)
		}
		// Only a template edited by hand can name a claim twice.
		if v, ok := claims[name]; ok && v != segs[i] {
			return nil, fmt.Errorf("origin %s takes the claim %s twice, and %s gives it two values", e.Name, name, id)
		}
		claims[name] = segs[i]
	}
	return claims, nil
}

// replaceFile writes data to path in one step, through a file of its own in
// the same directory, so that a reader sees the old content or the new and
// never a part.
func replaceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}
