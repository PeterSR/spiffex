// Package settings reads the issuer's settings file: who the issuer is,
// where its signing keys and its state live, and the operator's limits on
// what the state may make it do. The settings are not part of the state,
// and only the operator can change them, by editing the file and restarting
// the issuer.
package settings

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.yaml.in/yaml/v3"

	"github.com/PeterSR/spiffex/internal/state"
)

// Defaults for fields left out.
const (
	DefaultTokenTTL        = 5 * time.Minute
	DefaultActivationDelay = 30 * time.Minute

	DefaultVerifiersPerOrigin  = 4
	DefaultVerifiersTotal      = 16
	DefaultPerAddressPerMinute = 60
	DefaultPerAddressBurst     = 10
)

// Bounds on the lifetimes the issuer works with. The longest JWT-SVID
// lifetime is fixed by SPEC section 7.
const (
	MinTokenTTL           = 10 * time.Second
	MaxTokenTTL           = time.Hour
	MinActivationDelay    = 3 * time.Second
	maxSettingsFileLength = 1 << 20
)

// File is the settings file as written. Lists left out keep their defaults;
// lists given replace them.
type File struct {
	Issuer           string             `yaml:"issuer"`
	TrustDomain      string             `yaml:"trust_domain"`
	KeysDir          string             `yaml:"keys_dir"`
	TokenTTL         time.Duration      `yaml:"token_ttl"`
	ActivationDelay  time.Duration      `yaml:"activation_delay"`
	State            *StateLocation     `yaml:"state"`
	Management       bool               `yaml:"management"`
	ReadableFiles    *[]string          `yaml:"readable_files"`
	BearerTokenFiles *[]BearerTokenFile `yaml:"bearer_token_files"`
	Verifiers        [][]string         `yaml:"verifiers"`
	Fetch            Fetch              `yaml:"fetch"`
	VerifierLimits   VerifierLimits     `yaml:"verifier_limits"`
	VerifierUser     *VerifierUser      `yaml:"verifier_user"`
	TrustedProxies   []string           `yaml:"trusted_proxies"`
}

// VerifierUser is the numeric user and group exec verifiers run as.
type VerifierUser struct {
	UID *uint32 `yaml:"uid"`
	GID *uint32 `yaml:"gid"`
}

// StateLocation says where the state document is stored: exactly one of a
// file, a directory tree and a Kubernetes ConfigMap.
type StateLocation struct {
	File      string        `yaml:"file"`
	Dir       string        `yaml:"dir"`
	ConfigMap *ConfigMapRef `yaml:"configmap"`
}

// ConfigMapRef names a ConfigMap in the cluster the issuer runs in.
type ConfigMapRef struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

// BearerTokenFile is a file a jwt origin may send as a bearer token when
// fetching keys, and the hosts it may be sent to.
type BearerTokenFile struct {
	Path  string   `yaml:"path"`
	Hosts []string `yaml:"hosts"`
	// Paths, when given, are the only URL paths the token may be sent to.
	Paths []string `yaml:"paths"`
}

// Fetch governs the fetches the issuer makes for origins.
type Fetch struct {
	// RefusePrivateAddresses refuses to connect to loopback, link-local,
	// private and other non-public addresses, checked on the address
	// actually dialled.
	RefusePrivateAddresses bool `yaml:"refuse_private_addresses"`
	// AllowPrivateHosts are exempt from RefusePrivateAddresses.
	AllowPrivateHosts []string `yaml:"allow_private_hosts"`
}

// VerifierLimits bound how many exec verifiers run (SPEC section 5.4). Zero
// means the default.
type VerifierLimits struct {
	// PerOrigin bounds the verifiers running at once for one origin.
	PerOrigin int `yaml:"per_origin"`
	// Total bounds the verifiers running at once in all.
	Total int `yaml:"total"`
	// PerAddressPerMinute is the rate at which one client address may start
	// verifiers, and PerAddressBurst how many it may start at once after a
	// quiet spell.
	PerAddressPerMinute int `yaml:"per_address_per_minute"`
	PerAddressBurst     int `yaml:"per_address_burst"`
}

// Settings are the issuer's settings, checked and with defaults filled in.
type Settings struct {
	// Validation is what state validation needs: the issuer URL, the trust
	// domain, and the files and verifiers the state may name.
	Validation      state.Settings
	KeysDir         string
	TokenTTL        time.Duration
	ActivationDelay time.Duration
	State           StateLocation
	// Management serves the management API (SPEC section 8), which changes
	// the state in its storage.
	Management             bool
	RefusePrivateAddresses bool
	AllowPrivateHosts      []string
	VerifierLimits         VerifierLimits
	// VerifierUser is nil when verifiers run as the issuer's own user.
	VerifierUser *User
	// TrustedProxies are the peers whose X-Forwarded-For header names the
	// client.
	TrustedProxies []netip.Prefix
}

// User is a numeric user and group.
type User struct {
	UID uint32
	GID uint32
}

// Issuer returns the issuer URL.
func (s *Settings) Issuer() string { return s.Validation.Issuer }

// TrustDomain returns the trust domain.
func (s *Settings) TrustDomain() spiffeid.TrustDomain { return s.Validation.TrustDomain }

// Decode parses a settings file, refusing fields it does not know.
func Decode(data []byte) (*File, error) {
	if len(data) > maxSettingsFileLength {
		return nil, fmt.Errorf("the settings file is larger than %d bytes", maxSettingsFileLength)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the settings file is empty")
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("the settings file must be a single YAML document")
	}
	return &f, nil
}

// ReadFile reads and decodes the settings file at path.
func ReadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Validation returns what state validation needs from the file. It is all
// that spiffex check and explain read; the issuer reads the rest too, with
// Load.
func (f *File) Validation() (state.Settings, error) {
	if f.Issuer == "" || f.TrustDomain == "" {
		return state.Settings{}, errors.New("the issuer URL and trust domain are required")
	}
	td, err := spiffeid.TrustDomainFromString(f.TrustDomain)
	if err != nil {
		return state.Settings{}, fmt.Errorf("trust_domain: %w", err)
	}
	s := state.DefaultSettings(f.Issuer, td)
	if f.ReadableFiles != nil {
		s.ReadableFiles = nil
		for i, path := range *f.ReadableFiles {
			if !filepath.IsAbs(path) {
				return state.Settings{}, fmt.Errorf("readable_files[%d]: %q is not an absolute path", i, path)
			}
			s.ReadableFiles = append(s.ReadableFiles, path)
		}
	}
	if f.BearerTokenFiles != nil {
		s.BearerTokenFiles = nil
		for i, b := range *f.BearerTokenFiles {
			if err := b.check(); err != nil {
				return state.Settings{}, fmt.Errorf("bearer_token_files[%d]: %w", i, err)
			}
			s.BearerTokenFiles = append(s.BearerTokenFiles, state.BearerTokenFile{Path: b.Path, Hosts: b.Hosts, Paths: b.Paths})
		}
	}
	for i, argv := range f.Verifiers {
		if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
			return state.Settings{}, fmt.Errorf("verifiers[%d]: want an absolute path followed by fixed arguments", i)
		}
	}
	s.Verifiers = f.Verifiers
	if err := s.Check(); err != nil {
		return state.Settings{}, err
	}
	return s, nil
}

func (b BearerTokenFile) check() error {
	if !filepath.IsAbs(b.Path) {
		return fmt.Errorf("path %q is not an absolute path", b.Path)
	}
	if len(b.Hosts) == 0 {
		return errors.New("name at least one host the token may be sent to")
	}
	for _, h := range b.Hosts {
		host := h
		if hp, _, err := net.SplitHostPort(h); err == nil {
			host = hp
		}
		if !validHost(host) || strings.ContainsAny(h, "/@?# ") {
			return fmt.Errorf("%q is not a host, or a host and port", h)
		}
	}
	for _, p := range b.Paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?# ") {
			return fmt.Errorf("%q is not a URL path", p)
		}
	}
	return nil
}

func validHost(h string) bool {
	return h != "" && !strings.ContainsAny(h, "/@?#: ") || net.ParseIP(strings.Trim(h, "[]")) != nil
}

// Load reads the settings file at path and checks everything the issuer
// needs. Relative paths of keys_dir and the state are taken relative to the
// file's directory.
func Load(path string) (*Settings, error) {
	f, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := f.settings(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func (f *File) settings(baseDir string) (*Settings, error) {
	v, err := f.Validation()
	if err != nil {
		return nil, err
	}
	if f.KeysDir == "" {
		return nil, errors.New("keys_dir is required")
	}
	s := &Settings{
		Validation:             v,
		KeysDir:                resolve(baseDir, f.KeysDir),
		TokenTTL:               f.TokenTTL,
		ActivationDelay:        f.ActivationDelay,
		Management:             f.Management,
		RefusePrivateAddresses: f.Fetch.RefusePrivateAddresses,
		VerifierLimits:         f.VerifierLimits,
	}
	for i, h := range f.Fetch.AllowPrivateHosts {
		if !validHost(h) {
			return nil, fmt.Errorf("fetch.allow_private_hosts[%d]: %q is not a host name or address", i, h)
		}
		s.AllowPrivateHosts = append(s.AllowPrivateHosts, h)
	}
	if u := f.VerifierUser; u != nil {
		if u.UID == nil || u.GID == nil {
			return nil, errors.New("verifier_user: give both uid and gid")
		}
		s.VerifierUser = &User{UID: *u.UID, GID: *u.GID}
	}
	for i, cidr := range f.TrustedProxies {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			addr, addrErr := netip.ParseAddr(cidr)
			if addrErr != nil {
				return nil, fmt.Errorf("trusted_proxies[%d]: %q is not an address or CIDR", i, cidr)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		s.TrustedProxies = append(s.TrustedProxies, prefix.Masked())
	}
	if s.TokenTTL == 0 {
		s.TokenTTL = DefaultTokenTTL
	}
	if s.TokenTTL < MinTokenTTL || s.TokenTTL > MaxTokenTTL {
		return nil, fmt.Errorf("token_ttl %s is out of range (%s to %s)", s.TokenTTL, MinTokenTTL, MaxTokenTTL)
	}
	if s.ActivationDelay == 0 {
		s.ActivationDelay = DefaultActivationDelay
	}
	if s.ActivationDelay < MinActivationDelay {
		return nil, fmt.Errorf("activation_delay %s is too short (at least %s)", s.ActivationDelay, MinActivationDelay)
	}
	if s.State, err = f.stateLocation(baseDir); err != nil {
		return nil, err
	}
	if err := s.VerifierLimits.fill(); err != nil {
		return nil, fmt.Errorf("verifier_limits: %w", err)
	}
	return s, nil
}

func (f *File) stateLocation(baseDir string) (StateLocation, error) {
	if f.State == nil {
		return StateLocation{}, errors.New("state is required: give its file, dir or configmap")
	}
	loc := *f.State
	set := 0
	for _, given := range []bool{loc.File != "", loc.Dir != "", loc.ConfigMap != nil} {
		if given {
			set++
		}
	}
	if set != 1 {
		return StateLocation{}, errors.New("state: give exactly one of file, dir and configmap")
	}
	switch {
	case loc.File != "":
		loc.File = resolve(baseDir, loc.File)
	case loc.Dir != "":
		loc.Dir = resolve(baseDir, loc.Dir)
	default:
		if !dnsLabel(loc.ConfigMap.Namespace) || !dnsSubdomain(loc.ConfigMap.Name) {
			return StateLocation{}, errors.New("state.configmap: give a valid namespace and name")
		}
	}
	return loc, nil
}

func (l *VerifierLimits) fill() error {
	fields := []struct {
		name  string
		value *int
		def   int
	}{
		{"per_origin", &l.PerOrigin, DefaultVerifiersPerOrigin},
		{"total", &l.Total, DefaultVerifiersTotal},
		{"per_address_per_minute", &l.PerAddressPerMinute, DefaultPerAddressPerMinute},
		{"per_address_burst", &l.PerAddressBurst, DefaultPerAddressBurst},
	}
	for _, f := range fields {
		switch {
		case *f.value < 0:
			return fmt.Errorf("%s cannot be negative", f.name)
		case *f.value == 0:
			*f.value = f.def
		}
	}
	if l.PerOrigin > l.Total {
		return fmt.Errorf("per_origin (%d) is more than total (%d)", l.PerOrigin, l.Total)
	}
	return nil
}

func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) || baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}

func dnsLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func dnsSubdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel(label) {
			return false
		}
	}
	return true
}
