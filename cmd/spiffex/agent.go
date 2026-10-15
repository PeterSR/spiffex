package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/agent"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// credentialFlags are the flags shared by the commands that authenticate to
// the issuer as a workload.
type credentialFlags struct {
	issuerURL        *string
	trustDomain      *string
	clientID         *string
	keyFile          *string
	subjectTokenFile *string
	caFile           *string
}

func addCredentialFlags(fs interface {
	String(name, value, usage string) *string
}) credentialFlags {
	return credentialFlags{
		issuerURL:        fs.String("issuer", "", "issuer URL (required)"),
		trustDomain:      fs.String("trust-domain", "", "expected trust domain; defaults to the one the issuer announces"),
		clientID:         fs.String("client-id", "", "client id, for private_key_jwt authentication"),
		keyFile:          fs.String("key-file", "", "the workload's private key, for private_key_jwt authentication"),
		subjectTokenFile: fs.String("subject-token-file", "", "a token file to exchange, for token exchange (e.g. a Kubernetes projected service account token)"),
		caFile:           fs.String("ca-file", "", "PEM file of CA certificates to trust for the issuer, instead of the system roots"),
	}
}

func (f credentialFlags) credential() (agent.Credential, error) {
	byKey := *f.clientID != "" || *f.keyFile != ""
	byToken := *f.subjectTokenFile != ""
	switch {
	case byKey && byToken:
		return nil, errors.New("use either -client-id with -key-file, or -subject-token-file, not both")
	case byToken:
		return agent.SubjectTokenFile{Path: *f.subjectTokenFile}, nil
	case *f.clientID == "" || *f.keyFile == "":
		return nil, errors.New("give -client-id and -key-file, or -subject-token-file")
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
	fs := newFlagSet("agent", "-issuer URL -socket PATH (-client-id ID -key-file FILE | -subject-token-file FILE) [flags]")
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
