// Package config loads the issuer's configuration file: who the issuer is,
// where its keys live, and which workloads it issues identities to.
package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.yaml.in/yaml/v3"

	"github.com/PeterSR/spiffex/internal/issuer"
	"github.com/PeterSR/spiffex/internal/keyset"
)

// Config is the parsed configuration file.
type Config struct {
	Issuer          string         `yaml:"issuer"`
	TrustDomain     string         `yaml:"trust_domain"`
	KeysDir         string         `yaml:"keys_dir"`
	TokenTTL        time.Duration  `yaml:"token_ttl"`
	ActivationDelay time.Duration  `yaml:"activation_delay"`
	Clients         []ClientConfig `yaml:"clients"`
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
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
