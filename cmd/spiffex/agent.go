package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// credentialSynopsis is how the credential flags combine.
const credentialSynopsis = "(-client-id ID -key-file FILE | -subject-token-file FILE | -subject-token-command CMD) [-subject-token-type exec -origin NAME]"

// credentialFlags are the flags shared by the commands that authenticate to
// the issuer as a workload.
type credentialFlags struct {
	issuerURL           *string
	trustDomain         *string
	clientID            *string
	keyFile             *string
	subjectTokenFile    *string
	subjectTokenCommand *string
	subjectTokenType    *string
	origin              *string
	caFile              *string
}

func addCredentialFlags(fs interface {
	String(name, value, usage string) *string
}) credentialFlags {
	return credentialFlags{
		issuerURL:           fs.String("issuer", "", "issuer URL (required)"),
		trustDomain:         fs.String("trust-domain", "", "expected trust domain; defaults to the one the issuer announces"),
		clientID:            fs.String("client-id", "", "client id, <origin>/<member>, for private_key_jwt authentication"),
		keyFile:             fs.String("key-file", "", "the workload's private key, for private_key_jwt authentication"),
		subjectTokenFile:    fs.String("subject-token-file", "", "a file holding the proof to exchange, read for every request (a Kubernetes projected service account token, for one)"),
		subjectTokenCommand: fs.String("subject-token-command", "", `a command whose output is the proof to exchange, run without a shell for every request: words separated by spaces, or a JSON array such as ["/usr/bin/sign", "--for", "spiffex"]`),
		subjectTokenType:    fs.String("subject-token-type", "jwt", "what the proof is: jwt, or exec for the verifier of an exec origin"),
		origin:              fs.String("origin", "", "the exec origin whose verifier checks the proof, with -subject-token-type exec"),
		caFile:              fs.String("ca-file", "", "PEM file of CA certificates to trust for the issuer, instead of the system roots"),
	}
}

func (f credentialFlags) credential() (agent.Credential, error) {
	byKey := *f.clientID != "" || *f.keyFile != ""
	byToken := *f.subjectTokenFile != "" || *f.subjectTokenCommand != ""
	switch {
	case byKey && byToken:
		return nil, errors.New("use either -client-id with -key-file, or a subject token, not both")
	case byToken:
		return f.subjectToken()
	case *f.subjectTokenType != "jwt" || *f.origin != "":
		return nil, errors.New("-subject-token-type and -origin go with a subject token")
	case *f.clientID == "" || *f.keyFile == "":
		return nil, errors.New("give -client-id and -key-file, -subject-token-file, or -subject-token-command")
	}
	data, err := os.ReadFile(*f.keyFile)
	if err != nil {
		return nil, err
	}
	key, err := keyset.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", *f.keyFile, err)
	}
	return agent.PrivateKeyJWT{ClientID: *f.clientID, Key: key}, nil
}

func (f credentialFlags) subjectToken() (agent.Credential, error) {
	if *f.subjectTokenFile != "" && *f.subjectTokenCommand != "" {
		return nil, errors.New("use either -subject-token-file or -subject-token-command, not both")
	}
	cred := agent.SubjectToken{File: *f.subjectTokenFile}
	if *f.subjectTokenCommand != "" {
		argv, err := parseCommand(*f.subjectTokenCommand)
		if err != nil {
			return nil, fmt.Errorf("-subject-token-command: %w", err)
		}
		cred.Command = argv
	}
	switch *f.subjectTokenType {
	case "jwt":
		if *f.origin != "" {
			return nil, errors.New("-origin goes with -subject-token-type exec")
		}
	case "exec":
		if *f.origin == "" {
			return nil, errors.New("-subject-token-type exec needs -origin")
		}
		cred.Origin = *f.origin
	default:
		return nil, fmt.Errorf("-subject-token-type %q: want jwt or exec", *f.subjectTokenType)
	}
	return cred, nil
}

// parseCommand reads a command as a JSON array of strings, or as words
// separated by white space. Neither is a shell: there is no quoting,
// expansion or redirection.
func parseCommand(s string) ([]string, error) {
	var argv []string
	if strings.HasPrefix(strings.TrimSpace(s), "[") {
		if err := json.Unmarshal([]byte(s), &argv); err != nil {
			return nil, errors.New("not a JSON array of strings")
		}
	} else {
		argv = strings.Fields(s)
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("the command is empty")
	}
	return argv, nil
}

// issuerTarget validates the issuer flags and returns what discovery needs.
func (f credentialFlags) issuerTarget() (spiffeid.TrustDomain, *http.Client, error) {
	if *f.issuerURL == "" {
		return spiffeid.TrustDomain{}, nil, errors.New("-issuer is required")
	}
	var td spiffeid.TrustDomain
	if *f.trustDomain != "" {
		var err error
		if td, err = spiffeid.TrustDomainFromString(*f.trustDomain); err != nil {
			return td, nil, fmt.Errorf("-trust-domain: %w", err)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *f.caFile != "" {
		pem, err := os.ReadFile(*f.caFile)
		if err != nil {
			return td, nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return td, nil, fmt.Errorf("%s: no certificates found", *f.caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return td, &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func runAgent(ctx context.Context, args []string) error {
	fs := newFlagSet("agent", "-issuer URL -socket PATH "+credentialSynopsis+" [flags]")
	creds := addCredentialFlags(fs)
	socket := fs.String("socket", "", "Unix socket to serve the Workload API on (required)")
	socketMode := fs.String("socket-mode", "0600", "permissions of the socket file, in octal")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("-socket is required")
	}
	mode, err := strconv.ParseUint(*socketMode, 8, 32)
	if err != nil || mode > 0o777 {
		return fmt.Errorf("-socket-mode %q: want octal permissions such as 0600", *socketMode)
	}
	logger, err := newLogger(*logLevel)
	if err != nil {
		return err
	}
	cred, err := creds.credential()
	if err != nil {
		return err
	}

	client, err := discoverWithRetry(ctx, creds, logger)
	if err != nil {
		return err
	}
	a, err := agent.New(agent.Config{Issuer: client, Credential: cred, Logger: logger})
	if err != nil {
		return err
	}
	go a.Run(ctx)

	l, err := agent.Listen(*socket, os.FileMode(mode))
	if err != nil {
		return err
	}
	srv := a.NewServer()
	go func() {
		<-ctx.Done()
		// Bundle streams stay open as long as their clients do, so a graceful
		// stop would wait for every workload to disconnect.
		srv.Stop()
	}()
	logger.Info("agent serving the Workload API", "socket", *socket, "issuer", *creds.issuerURL, "trust_domain", client.TrustDomain().Name())
	return srv.Serve(l)
}

// discoverWithRetry keeps trying discovery, because an agent often starts
// alongside the issuer or before the network is ready. It gives up at once
// when the issuer answers in a way retrying cannot fix.
func discoverWithRetry(ctx context.Context, creds credentialFlags, logger *slog.Logger) (*agent.IssuerClient, error) {
	td, httpClient, err := creds.issuerTarget()
	if err != nil {
		return nil, err
	}
	backoff := time.Second
	for {
		client, err := agent.Discover(ctx, *creds.issuerURL, td, httpClient)
		var configErr *agent.ConfigError
		switch {
		case err == nil:
			return client, nil
		case errors.As(err, &configErr):
			return nil, err
		}
		logger.Warn("issuer discovery failed, retrying", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
