package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/manage"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

const manageUsage = `Usage: spiffex manage <command> [flags]

Commands:
  get state                       the state, as far as you may read it
  get origin|grant|provider NAME  one object
  put origin|grant|provider NAME -f FILE
                                  create or replace an object from a YAML or JSON file
  put member ORIGIN MEMBER -key FILE
                                  add or replace a member of a keys origin, with its public keys
  delete origin|grant|provider NAME
  delete member ORIGIN MEMBER
  check -f FILE                   validate a state document without storing it

The management token comes from the Workload API (-socket, or
SPIFFE_ENDPOINT_SOCKET), or from the issuer's token endpoint with
-client-id and -key-file, -subject-token-file or -subject-token-command.
Flags may come before or after the command.
`

// maxManageResponse bounds what is read from the management API: the state
// is at most 1 MiB as JSON, a little more when indented.
const maxManageResponse = 4 << 20

type manageCall struct {
	method string
	path   string
	body   []byte
	// what describes the object for messages, such as "origin web".
	what string
}

func runManage(ctx context.Context, args []string) error {
	fs := newFlagSet("manage", "<command> ... [flags]")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), manageUsage+"\nFlags (each can also be set as SPIFFEX_<FLAG> in the environment):\n")
		fs.PrintDefaults()
	}
	creds := addCredentialFlags(fs)
	socket := fs.String("socket", "", "the Workload API socket to get management tokens from, such as an agent's")
	file := fs.String("f", "", "for put and check: the document to send, YAML or JSON")
	keyFile := fs.String("key", "", "for put member: the member's public keys, PEM PUBLIC KEY blocks or a JWK or JWK Set")
	ifMatch := fs.String("if-match", "", "for put and delete: change the state only if it is still at this version, as an earlier answer gave it")
	words, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	call, err := manageRequest(words, *file, *keyFile)
	if err != nil {
		fs.Usage()
		return usageError{err}
	}
	td, httpClient, err := creds.issuerTarget()
	if err != nil {
		return err
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	endpoint, err := managementEndpoint(ctx, httpClient, *creds.issuerURL)
	if err != nil {
		return err
	}
	token, err := managementToken(ctx, creds, *socket, td, httpClient, endpoint)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, call.method, endpoint+call.path, bytes.NewReader(call.body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if call.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if *ifMatch != "" && call.method != http.MethodGet {
		req.Header.Set("If-Match", quoteETag(*ifMatch))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManageResponse))
	if err != nil {
		return err
	}
	return printAnswer(call, resp, body)
}

// manageRequest turns the command's words into a request.
func manageRequest(words []string, file, keyFile string) (*manageCall, error) {
	if len(words) == 0 {
		return nil, errors.New("no command given")
	}
	verb, rest := words[0], words[1:]
	kind := ""
	if len(rest) > 0 {
		kind, rest = rest[0], rest[1:]
	}
	section := map[string]string{"origin": "origins", "grant": "grants", "provider": "providers"}[kind]
	want := func(n int, names string) error {
		if len(rest) != n {
			return fmt.Errorf("%s %s takes %s", verb, kind, names)
		}
		return nil
	}
	call := &manageCall{}
	switch {
	case verb == "check":
		if kind != "" || file == "" {
			return nil, errors.New("check takes -f FILE and nothing else")
		}
		call.method, call.path, call.what = http.MethodPost, "/check", "the state in "+file
		body, err := documentJSON(file)
		call.body = body
		return call, err
	case verb == "get" && kind == "state":
		if err := want(0, "no name"); err != nil {
			return nil, err
		}
		call.method, call.path, call.what = http.MethodGet, "/state", "the state"
		return call, nil
	case kind == "member" && (verb == "put" || verb == "delete"):
		if err := want(2, "an origin and a member name"); err != nil {
			return nil, err
		}
		if err := checkNames("origin", rest[0], "member", rest[1]); err != nil {
			return nil, err
		}
		call.path = "/origins/" + url.PathEscape(rest[0]) + "/members/" + url.PathEscape(rest[1])
		call.what = "member " + rest[1] + " of origin " + rest[0]
		if verb == "delete" {
			call.method = http.MethodDelete
			return call, nil
		}
		if keyFile == "" {
			return nil, errors.New("put member takes -key FILE")
		}
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		keys, err := store.MemberKeys(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyFile, err)
		}
		call.method = http.MethodPut
		call.body, err = json.Marshal(state.Member{Keys: keys})
		return call, err
	case section == "":
		return nil, fmt.Errorf("unknown command %q", strings.Join(words, " "))
	}
	if err := want(1, "a name"); err != nil {
		return nil, err
	}
	if err := checkNames(kind, rest[0]); err != nil {
		return nil, err
	}
	call.path, call.what = "/"+section+"/"+url.PathEscape(rest[0]), kind+" "+rest[0]
	switch verb {
	case "get":
		call.method = http.MethodGet
	case "delete":
		call.method = http.MethodDelete
	case "put":
		if file == "" {
			return nil, fmt.Errorf("put %s takes -f FILE", kind)
		}
		body, err := documentJSON(file)
		if err != nil {
			return nil, err
		}
		call.method, call.body = http.MethodPut, body
	default:
		return nil, fmt.Errorf("unknown command %q", verb)
	}
	return call, nil
}

// checkNames refuses names that no object can have, before they go into a
// URL path: a member named .. would otherwise name the path above it.
// Arguments come in pairs of kind and name.
func checkNames(pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		kind, name := pairs[i], pairs[i+1]
		valid := state.ValidName(name)
		if kind == "member" {
			valid = state.ValidSegment(name)
		}
		if !valid {
			return fmt.Errorf("%q cannot be the name of a %s", name, kind)
		}
	}
	return nil
}

// documentJSON reads a YAML or JSON document and returns it as JSON, which
// is what the management API takes.
func documentJSON(file string) ([]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	tree, err := state.DecodeTree(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return json.Marshal(tree)
}

// managementEndpoint reads the management endpoint from the issuer's
// discovery document, which names it only when the API is enabled.
func managementEndpoint(ctx context.Context, client *http.Client, issuerURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL+issuer.DiscoveryPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery: %s", resp.Status)
	}
	var doc struct {
		Issuer     string `json:"issuer"`
		Management string `json:"spiffex_management_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	switch {
	case doc.Issuer != issuerURL:
		return "", fmt.Errorf("discovery: issuer %q does not match %q", doc.Issuer, issuerURL)
	case doc.Management == "":
		return "", fmt.Errorf("the issuer %s does not serve the management API; it is enabled with management: true in its settings", issuerURL)
	case doc.Management != state.ManagementAudience(issuerURL):
		return "", fmt.Errorf("discovery: management endpoint %q is not %s", doc.Management, state.ManagementAudience(issuerURL))
	}
	return doc.Management, nil
}

// managementToken gets a JWT-SVID for the management endpoint, alone: from
// a Workload API socket, or from the issuer with the workload's own proof.
func managementToken(ctx context.Context, creds credentialFlags, socket string, td spiffeid.TrustDomain, client *http.Client, audience string) (string, error) {
	ownProof := *creds.clientID != "" || *creds.keyFile != "" || *creds.subjectTokenFile != "" || *creds.subjectTokenCommand != ""
	if socket != "" && ownProof {
		return "", usageError{errors.New("use either -socket or the workload's own proof, not both")}
	}
	if socket != "" || !ownProof && os.Getenv("SPIFFE_ENDPOINT_SOCKET") != "" {
		var opts []workloadapi.ClientOption
		if socket != "" {
			addr := socket
			if !strings.Contains(addr, "://") {
				abs, err := filepath.Abs(socket)
				if err != nil {
					return "", err
				}
				addr = "unix://" + abs
			}
			opts = append(opts, workloadapi.WithAddr(addr))
		}
		source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(opts...))
		if err != nil {
			return "", fmt.Errorf("the Workload API: %w", err)
		}
		defer source.Close()
		svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
		if err != nil {
			return "", fmt.Errorf("fetching a management token from the Workload API: %w", err)
		}
		return svid.Marshal(), nil
	}
	cred, err := creds.credential()
	if err != nil {
		return "", usageError{fmt.Errorf("%w, or -socket", err)}
	}
	ic, err := agent.Discover(ctx, *creds.issuerURL, td, client)
	if err != nil {
		return "", err
	}
	token, err := ic.FetchToken(ctx, cred, []string{audience})
	if err != nil {
		return "", fmt.Errorf("fetching a management token: %w", err)
	}
	return token.Value, nil
}

func quoteETag(v string) string {
	if v == "*" || strings.HasPrefix(v, `"`) {
		return v
	}
	return `"` + v + `"`
}

// printAnswer prints a successful answer, or returns the API's reasons for
// refusing as an error.
func printAnswer(call *manageCall, resp *http.Response, body []byte) error {
	version := strings.Trim(resp.Header.Get("ETag"), `"`)
	if resp.StatusCode >= 300 {
		var e manage.ErrorBody
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			return fmt.Errorf("%s: %s", call.what, resp.Status)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %s: %s", call.what, resp.Status, e.Error)
		for _, p := range e.Problems {
			if p.Path == "" {
				fmt.Fprintf(&b, "\n  %s", p.Message)
			} else {
				fmt.Fprintf(&b, "\n  %s: %s", p.Path, p.Message)
			}
		}
		return errors.New(b.String())
	}
	switch call.method {
	case http.MethodGet:
		os.Stdout.Write(body)
		if resp.Header.Get(manage.ProviderSourceHeader) == "shipped" {
			fmt.Fprintf(os.Stderr, "note: %s ships with spiffex; the state has no provider of that name\n", call.what)
		}
		if overrides := resp.Header.Get(manage.OverridesHeader); overrides != "" {
			fmt.Fprintf(os.Stderr, "note: these providers in the state override the shipped ones of their names: %s\n", overrides)
		}
		fmt.Fprintf(os.Stderr, "version %q\n", version)
	case http.MethodPut:
		verb := "updated"
		if resp.StatusCode == http.StatusCreated {
			verb = "created"
		}
		fmt.Printf("%s %s, version %q\n", verb, call.what, version)
	case http.MethodDelete:
		fmt.Printf("removed %s, version %q\n", call.what, version)
	case http.MethodPost:
		var result manage.CheckResult
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("%s: %w", call.what, err)
		}
		for _, p := range result.Problems {
			fmt.Printf("%s\n", state.Problem{Path: p.Path, Message: p.Message})
		}
		for _, name := range result.Overrides {
			fmt.Printf("note: provider %s overrides the shipped provider of that name\n", name)
		}
		for _, name := range result.X509UnderRestriction {
			fmt.Printf("warning: origin %s lists x509 and has an audience restriction, which does not cover its X.509-SVIDs\n", name)
		}
		if !result.Valid {
			return fmt.Errorf("%s is invalid", call.what)
		}
		fmt.Printf("%s is valid\n", call.what)
	}
	return nil
}
