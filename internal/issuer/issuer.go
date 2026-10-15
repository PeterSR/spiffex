// Package issuer implements the spiffex issuer: OIDC discovery, the JWKS, the
// SPIFFE bundle endpoint and the token endpoint that mints JWT-SVIDs.
package issuer

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/keyset"
)

// Paths of the endpoints, relative to the issuer URL.
const (
	DiscoveryPath     = "/.well-known/openid-configuration"
	OAuthMetadataPath = "/.well-known/oauth-authorization-server"
	JWKSPath          = "/jwks"
	BundlePath        = "/bundle"
	TokenPath         = "/token"
	HealthPath        = "/healthz"
)

// Defaults for Config fields left zero.
const (
	DefaultTokenTTL        = 5 * time.Minute
	DefaultActivationDelay = 30 * time.Minute
)

// KeySource supplies the current signing keys and their sequence number.
// keyset.Watcher implements it.
type KeySource interface {
	Current() (set *keyset.Set, sequence uint64, changed <-chan struct{})
}

// Config configures an Issuer.
type Config struct {
	// URL is the issuer URL: https (or http for local development), no query,
	// no fragment, no trailing slash.
	URL         string
	TrustDomain spiffeid.TrustDomain
	Keys        KeySource
	// Clients enables the client_credentials grant with private_key_jwt.
	Clients ClientSource
	// TokenTTL is the lifetime of issued JWT-SVIDs.
	TokenTTL time.Duration
	// ActivationDelay is how long a new key is published before it signs.
	ActivationDelay time.Duration
	// RefreshHint is the spiffe_refresh_hint published in the bundle, in
	// whole seconds. It defaults to a fifth of ActivationDelay and must not
	// exceed a third of it.
	RefreshHint time.Duration
	Logger      *slog.Logger
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Issuer serves the issuer endpoints. Create it with New.
type Issuer struct {
	cfg      Config
	basePath string
	replay   *replayCache
}

// New validates cfg, fills in defaults and returns an Issuer.
func New(cfg Config) (*Issuer, error) {
	u, err := ValidateURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.TrustDomain.IsZero() {
		return nil, errors.New("trust domain is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("a key source is required")
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = DefaultTokenTTL
	}
	if cfg.TokenTTL < 10*time.Second || cfg.TokenTTL > 24*time.Hour {
		return nil, fmt.Errorf("token TTL %s is out of range (10s to 24h)", cfg.TokenTTL)
	}
	if cfg.ActivationDelay == 0 {
		cfg.ActivationDelay = DefaultActivationDelay
	}
	if cfg.ActivationDelay < 3*time.Second {
		return nil, fmt.Errorf("activation delay %s is too short (at least 3s)", cfg.ActivationDelay)
	}
	if cfg.RefreshHint == 0 {
		cfg.RefreshHint = max(cfg.ActivationDelay/5, time.Second)
	}
	cfg.RefreshHint = cfg.RefreshHint.Truncate(time.Second)
	if cfg.RefreshHint < time.Second {
		return nil, errors.New("refresh hint must be at least one second")
	}
	if cfg.RefreshHint > cfg.ActivationDelay/3 {
		return nil, fmt.Errorf("refresh hint %s exceeds a third of the activation delay %s", cfg.RefreshHint, cfg.ActivationDelay)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Issuer{cfg: cfg, basePath: u.Path, replay: newReplayCache()}, nil
}

// ValidateURL checks that raw is usable as an issuer URL and returns it parsed.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("issuer URL: %w", err)
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("issuer URL %q: scheme must be https (or http for local development)", raw)
	case u.Host == "":
		return nil, fmt.Errorf("issuer URL %q: host is required", raw)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "":
		return nil, fmt.Errorf("issuer URL %q: must not have a query, fragment or user info", raw)
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("issuer URL %q: must not end with a slash", raw)
	case u.Path != "" && path.Clean(u.Path) != u.Path:
		return nil, fmt.Errorf("issuer URL %q: path must be clean", raw)
	case strings.ContainsAny(u.Path, "{}") || u.String() != raw:
		return nil, fmt.Errorf("issuer URL %q: must be written in canonical form, without characters that need escaping", raw)
	}
	return u, nil
}

// URL returns the issuer URL.
func (iss *Issuer) URL() string { return iss.cfg.URL }

// TrustDomain returns the issuer's trust domain.
func (iss *Issuer) TrustDomain() spiffeid.TrustDomain { return iss.cfg.TrustDomain }

// TokenEndpoint returns the token endpoint URL.
func (iss *Issuer) TokenEndpoint() string { return iss.cfg.URL + TokenPath }

// Handler returns the HTTP handler serving every endpoint under the issuer
// URL's path.
func (iss *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+iss.basePath+DiscoveryPath, iss.handleDiscovery)
	// RFC 8414 inserts the well-known segment between host and path.
	mux.HandleFunc("GET "+OAuthMetadataPath+iss.basePath, iss.handleDiscovery)
	mux.HandleFunc("GET "+iss.basePath+JWKSPath, iss.handleJWKS)
	mux.HandleFunc("GET "+iss.basePath+BundlePath, iss.handleBundle)
	mux.HandleFunc("POST "+iss.basePath+TokenPath, iss.handleToken)
	mux.HandleFunc("GET "+iss.basePath+HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (iss *Issuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	set, _, _ := iss.cfg.Keys.Current()
	doc := map[string]any{
		"issuer":                                iss.cfg.URL,
		"jwks_uri":                              iss.cfg.URL + JWKSPath,
		"token_endpoint":                        iss.TokenEndpoint(),
		"grant_types_supported":                 iss.grantTypes(),
		"token_endpoint_auth_methods_supported": iss.authMethods(),
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algorithms(set),
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "jti"},
		"spiffe_bundle_endpoint":                iss.cfg.URL + BundlePath,
		"spiffe_trust_domain":                   iss.cfg.TrustDomain.Name(),
	}
	if iss.cfg.Clients != nil {
		doc["token_endpoint_auth_signing_alg_values_supported"] = assertionAlgorithms
	}
	writeJSON(w, http.StatusOK, doc, iss.publicCache())
}

func (iss *Issuer) grantTypes() []string {
	grants := []string{}
	if iss.cfg.Clients != nil {
		grants = append(grants, GrantClientCredentials)
	}
	return grants
}

func (iss *Issuer) authMethods() []string {
	methods := []string{}
	if iss.cfg.Clients != nil {
		methods = append(methods, "private_key_jwt")
	}
	return methods
}

func (iss *Issuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set, _, _ := iss.cfg.Keys.Current()
	keys := set.Keys()
	jwks := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	for _, k := range keys {
		jwk := k.Public()
		jwk.Use = "sig"
		jwks.Keys = append(jwks.Keys, jwk)
	}
	writeJSON(w, http.StatusOK, jwks, iss.publicCache())
}

func (iss *Issuer) handleBundle(w http.ResponseWriter, _ *http.Request) {
	body, err := iss.Bundle()
	if err != nil {
		iss.cfg.Logger.Error("building the SPIFFE bundle failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, &oauthError{Code: "server_error"}, "no-store")
		return
	}
	writeBody(w, http.StatusOK, body, iss.publicCache())
}

// Bundle returns the trust domain's SPIFFE bundle document.
func (iss *Issuer) Bundle() ([]byte, error) {
	set, seq, _ := iss.cfg.Keys.Current()
	b := spiffebundle.New(iss.cfg.TrustDomain)
	for _, k := range set.Keys() {
		if err := b.AddJWTAuthority(k.ID, k.Signer.Public()); err != nil {
			return nil, err
		}
	}
	b.SetSequenceNumber(seq)
	b.SetRefreshHint(iss.cfg.RefreshHint)
	return b.Marshal()
}

// Mint signs a JWT-SVID for id with the given audiences.
func (iss *Issuer) Mint(id spiffeid.ID, audiences []string) (token string, expires time.Time, err error) {
	if !id.MemberOf(iss.cfg.TrustDomain) {
		return "", time.Time{}, fmt.Errorf("%s is not in trust domain %s", id, iss.cfg.TrustDomain)
	}
	audiences, err = iss.checkAudiences(audiences)
	if err != nil {
		return "", time.Time{}, err
	}
	now := iss.cfg.Now().Truncate(time.Second)
	set, _, _ := iss.cfg.Keys.Current()
	key := set.Active(now, iss.cfg.ActivationDelay)

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       jose.JSONWebKey{Key: key.Signer, KeyID: key.ID, Algorithm: string(key.Algorithm)},
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", time.Time{}, err
	}
	expires = now.Add(iss.cfg.TokenTTL)
	claims := jwt.Claims{
		Issuer:   iss.cfg.URL,
		Subject:  id.String(),
		Audience: jwt.Audience(audiences),
		Expiry:   jwt.NewNumericDate(expires),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       rand.Text(),
	}
	token, err = jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// checkAudiences validates and deduplicates requested audiences. An audience
// naming the issuer itself is refused so that a JWT-SVID can never pass for a
// client assertion aimed at this issuer.
func (iss *Issuer) checkAudiences(audiences []string) ([]string, error) {
	if len(audiences) == 0 {
		return nil, errInvalidRequest("audience is required")
	}
	var out []string
	for _, aud := range audiences {
		if err := ValidateAudience(aud); err != nil {
			return nil, errInvalidRequest("%v", err)
		}
		if aud == iss.cfg.URL || aud == iss.TokenEndpoint() {
			return nil, errInvalidTarget
		}
		if !slices.Contains(out, aud) {
			out = append(out, aud)
		}
	}
	if len(out) > MaxAudiences {
		return nil, errInvalidRequest("at most %d audiences may be requested", MaxAudiences)
	}
	return out, nil
}

func algorithms(set *keyset.Set) []string {
	var algs []string
	for _, k := range set.Keys() {
		if !slices.Contains(algs, string(k.Algorithm)) {
			algs = append(algs, string(k.Algorithm))
		}
	}
	return algs
}

// publicCache is the Cache-Control value for the published key material: no
// longer than the refresh hint, so rotation timing holds for consumers that
// honour HTTP caching but not the bundle's hint.
func (iss *Issuer) publicCache() string {
	return fmt.Sprintf("public, max-age=%d", int(iss.cfg.RefreshHint.Seconds()))
}

func writeJSON(w http.ResponseWriter, status int, v any, cacheControl string) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeBody(w, status, append(body, '\n'), cacheControl)
}

func writeBody(w http.ResponseWriter, status int, body []byte, cacheControl string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", cacheControl)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
