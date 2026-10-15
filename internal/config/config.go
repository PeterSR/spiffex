// Package config loads the issuer's configuration file: who the issuer is,
// where its keys live, and which workloads it issues identities to.
package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.yaml.in/yaml/v3"

	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// Config is the parsed configuration file.
type Config struct {
	Issuer          string           `yaml:"issuer"`
	TrustDomain     string           `yaml:"trust_domain"`
	KeysDir         string           `yaml:"keys_dir"`
	TokenTTL        time.Duration    `yaml:"token_ttl"`
	ActivationDelay time.Duration    `yaml:"activation_delay"`
	Clients         []ClientConfig   `yaml:"clients"`
	Upstreams       []UpstreamConfig `yaml:"upstreams"`
}

// UpstreamConfig trusts another issuer's tokens for token exchange.
type UpstreamConfig struct {
	Name     string `yaml:"name"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// Exactly one of JWKSFile, JWKSURI and Discovery says where the keys are.
	JWKSFile  string `yaml:"jwks_file"`
	JWKSURI   string `yaml:"jwks_uri"`
	Discovery bool   `yaml:"discovery"`
	// CAFile replaces the system roots when fetching keys.
	CAFile string `yaml:"ca_file"`
	// BearerTokenFile is sent as a bearer token when fetching keys.
	BearerTokenFile string `yaml:"bearer_token_file"`
	// MaxTokenLifetime refuses subject tokens meant to live longer (exp
	// minus iat). Default one hour.
	MaxTokenLifetime time.Duration `yaml:"max_token_lifetime"`
	// Shared says whether anyone can get tokens from this issuer (a public CI
	// or cloud provider). It must be stated for keys fetched over the network,
	// and when true every rule must match on at least one claim.
	Shared *bool        `yaml:"shared"`
	Rules  []RuleConfig `yaml:"rules"`
}

// DefaultMaxTokenLifetime is the longest subject token lifetime accepted
// unless an upstream says otherwise.
const DefaultMaxTokenLifetime = time.Hour

// knownShared are issuers that hand tokens to anyone who asks: the rules for
// them must always pin an owner, whatever the configuration says.
var knownShared = []string{
	"https://token.actions.githubusercontent.com",
	"https://gitlab.com",
	"https://accounts.google.com",
	"accounts.google.com",
	"https://oidc.circleci.com/",
	"https://login.microsoftonline.com/",
	"https://sts.windows.net/",
	"https://app.terraform.io",
	"https://vstoken.actions.githubusercontent.com",
}

func isKnownShared(issuer string) bool {
	for _, known := range knownShared {
		if issuer == strings.TrimSuffix(known, "/") || strings.HasSuffix(known, "/") && strings.HasPrefix(issuer, known) {
			return true
		}
	}
	return false
}

// RuleConfig maps matching upstream tokens to a SPIFFE ID.
type RuleConfig struct {
	Match    map[string]string `yaml:"match"`
	Require  []string          `yaml:"require"`
	SPIFFEID string            `yaml:"spiffe_id"`
}

// ClientConfig registers one workload that authenticates with private_key_jwt.
type ClientConfig struct {
	ClientID   string   `yaml:"client_id"`
	SPIFFEID   string   `yaml:"spiffe_id"`
	PublicKeys []KeyRef `yaml:"public_keys"`
	// Audiences, when set, is the only audiences the client may request.
	Audiences []string `yaml:"audiences"`
}

// KeyRef is a public key given inline as PEM or as a path to a PEM file.
// Relative paths are resolved against the configuration file's directory.
type KeyRef struct {
	PEM  string `yaml:"pem"`
	File string `yaml:"file"`
}

// Loaded is a validated configuration, ready to use.
type Loaded struct {
	Issuer          string
	TrustDomain     spiffeid.TrustDomain
	KeysDir         string
	TokenTTL        time.Duration
	ActivationDelay time.Duration
	Clients         map[string]issuer.Client
	Upstreams       []exchange.Upstream
	// upstreamsRaw is kept to detect changes, which need a restart.
	upstreamsRaw []UpstreamConfig
	// keyFiles are the public key files the configuration refers to; a
	// change to one of them is a change to the configuration.
	keyFiles []string
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseFile(path, data)
}

func parseFile(path string, data []byte) (*Loaded, error) {
	loaded, err := Parse(data, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return loaded, nil
}

// Parse validates a configuration document. baseDir resolves relative paths.
func Parse(data []byte, baseDir string) (*Loaded, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the configuration is empty")
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("the configuration must be a single YAML document")
	}

	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("trust_domain: %w", err)
	}
	if cfg.KeysDir == "" {
		return nil, errors.New("keys_dir is required")
	}
	out := &Loaded{
		Issuer:          cfg.Issuer,
		TrustDomain:     td,
		KeysDir:         resolve(baseDir, cfg.KeysDir),
		TokenTTL:        cfg.TokenTTL,
		ActivationDelay: cfg.ActivationDelay,
		Clients:         make(map[string]issuer.Client, len(cfg.Clients)),
	}
	keyOwners := map[string]string{}
	for i, c := range cfg.Clients {
		for _, ref := range c.PublicKeys {
			if ref.File != "" {
				out.keyFiles = append(out.keyFiles, resolve(baseDir, ref.File))
			}
		}
		client, err := parseClient(c, td, baseDir)
		if err != nil {
			return nil, fmt.Errorf("clients[%d]: %w", i, err)
		}
		if _, dup := out.Clients[client.ID]; dup {
			return nil, fmt.Errorf("clients[%d]: client_id %q is registered twice", i, client.ID)
		}
		// One key under two clients would let its holder choose either identity.
		for _, key := range client.PublicKeys {
			kid, err := keyset.Thumbprint(key)
			if err != nil {
				return nil, fmt.Errorf("clients[%d]: %w", i, err)
			}
			if owner, taken := keyOwners[kid]; taken {
				return nil, fmt.Errorf("clients[%d]: a public key of %q is already registered for %q", i, client.ID, owner)
			}
			keyOwners[kid] = client.ID
		}
		out.Clients[client.ID] = client
	}
	for i, u := range cfg.Upstreams {
		upstream, err := parseUpstream(u, baseDir)
		if err != nil {
			return nil, fmt.Errorf("upstreams[%d]: %w", i, err)
		}
		out.Upstreams = append(out.Upstreams, upstream)
	}
	out.upstreamsRaw = cfg.Upstreams
	return out, nil
}

func parseClient(c ClientConfig, td spiffeid.TrustDomain, baseDir string) (issuer.Client, error) {
	if c.ClientID == "" {
		return issuer.Client{}, errors.New("client_id is required")
	}
	id, err := spiffeid.FromString(c.SPIFFEID)
	if err != nil {
		return issuer.Client{}, fmt.Errorf("spiffe_id: %w", err)
	}
	if !id.MemberOf(td) {
		return issuer.Client{}, fmt.Errorf("spiffe_id %s is not in trust domain %s", id, td)
	}
	if len(c.PublicKeys) == 0 {
		return issuer.Client{}, errors.New("at least one public key is required")
	}
	client := issuer.Client{ID: c.ClientID, SPIFFEID: id}
	for j, ref := range c.PublicKeys {
		key, err := ref.load(baseDir)
		if err != nil {
			return issuer.Client{}, fmt.Errorf("public_keys[%d]: %w", j, err)
		}
		client.PublicKeys = append(client.PublicKeys, key)
	}
	for _, aud := range c.Audiences {
		if err := issuer.ValidateAudience(aud); err != nil {
			return issuer.Client{}, fmt.Errorf("audiences: %w", err)
		}
	}
	client.Audiences = c.Audiences
	return client, nil
}

func parseUpstream(u UpstreamConfig, baseDir string) (exchange.Upstream, error) {
	if u.Name == "" {
		return exchange.Upstream{}, errors.New("name is required")
	}
	sources := 0
	for _, set := range []bool{u.JWKSFile != "", u.JWKSURI != "", u.Discovery} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return exchange.Upstream{}, fmt.Errorf("%s: set exactly one of jwks_file, jwks_uri and discovery", u.Name)
	}
	if u.Discovery && !strings.HasPrefix(u.Issuer, "https://") {
		return exchange.Upstream{}, fmt.Errorf("%s: discovery needs an https issuer", u.Name)
	}
	if u.JWKSURI != "" && !strings.HasPrefix(u.JWKSURI, "https://") {
		return exchange.Upstream{}, fmt.Errorf("%s: jwks_uri must be https", u.Name)
	}
	if u.JWKSFile != "" && (u.CAFile != "" || u.BearerTokenFile != "") {
		return exchange.Upstream{}, fmt.Errorf("%s: ca_file and bearer_token_file only apply to fetched keys", u.Name)
	}
	if u.MaxTokenLifetime < 0 {
		return exchange.Upstream{}, fmt.Errorf("%s: max_token_lifetime must be positive", u.Name)
	}
	shared := u.Shared != nil && *u.Shared
	switch {
	case isKnownShared(u.Issuer):
		if u.Shared != nil && !*u.Shared {
			return exchange.Upstream{}, fmt.Errorf("%s: %s gives tokens to anyone; it cannot be marked shared: false", u.Name, u.Issuer)
		}
		shared = true
	case u.Shared == nil && u.JWKSFile == "":
		return exchange.Upstream{}, fmt.Errorf("%s: say whether anyone can get tokens from %s with shared: true or shared: false", u.Name, u.Issuer)
	}
	var keys exchange.KeySource
	if u.JWKSFile != "" {
		keys = &exchange.FileKeys{Path: resolve(baseDir, u.JWKSFile)}
	} else {
		client, err := httpClient(resolve(baseDir, u.CAFile), u.CAFile != "")
		if err != nil {
			return exchange.Upstream{}, fmt.Errorf("%s: %w", u.Name, err)
		}
		remote := &exchange.RemoteKeys{URL: u.JWKSURI, Client: client}
		if u.Discovery {
			remote.URL, remote.Discover = u.Issuer, true
		}
		if u.BearerTokenFile != "" {
			remote.BearerTokenFile = resolve(baseDir, u.BearerTokenFile)
		}
		keys = remote
	}
	maxLifetime := u.MaxTokenLifetime
	if maxLifetime == 0 {
		maxLifetime = DefaultMaxTokenLifetime
	}
	upstream := exchange.Upstream{Name: u.Name, Issuer: u.Issuer, Audience: u.Audience, Keys: keys, MaxTokenLifetime: maxLifetime}
	for i, r := range u.Rules {
		if shared && len(r.Match) == 0 {
			return exchange.Upstream{}, fmt.Errorf("%s: rules[%d]: a shared upstream's rules must match on a claim that identifies the owner", u.Name, i)
		}
		upstream.Rules = append(upstream.Rules, exchange.Rule{Match: r.Match, Require: r.Require, SPIFFEID: r.SPIFFEID})
	}
	return upstream, nil
}

// httpClient returns a client for fetching upstream keys that never follows
// redirects and, with a CA file, trusts only those roots.
func httpClient(caFile string, useCA bool) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if useCA {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("%s: no certificates found", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (r KeyRef) load(baseDir string) (crypto.PublicKey, error) {
	var data []byte
	switch {
	case r.PEM != "" && r.File != "":
		return nil, errors.New("set pem or file, not both")
	case r.PEM != "":
		data = []byte(r.PEM)
	case r.File != "":
		var err error
		if data, err = os.ReadFile(resolve(baseDir, r.File)); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("set pem or file")
	}
	return ParsePublicKey(data)
}

// ParsePublicKey parses a PEM-encoded SubjectPublicKeyInfo holding an EC P-256
// or an RSA (at least 2048 bits) public key.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("more than one PEM block; give each key separately")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type %q, want PUBLIC KEY", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("EC curve %s, want P-256", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key of %d bits is too small, want at least 2048", k.N.BitLen())
		}
	default:
		return nil, fmt.Errorf("unsupported public key type %T", key)
	}
	return key, nil
}

func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) || baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}
