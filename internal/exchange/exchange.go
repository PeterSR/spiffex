// Package exchange verifies tokens from upstream issuers (a Kubernetes
// cluster, a CI provider, a cloud) and maps them to SPIFFE IDs, for the token
// exchange grant (SPEC section 3.3).
package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// upstreamAlgorithms are the signature algorithms accepted on subject
// tokens: asymmetric only, so a public JWKS can never verify an HMAC.
var upstreamAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// clockSkew is tolerated on every time comparison against an upstream's clock.
const clockSkew = 30 * time.Second

// ErrRejected is wrapped by every error that means the subject token is not
// acceptable, as opposed to the exchanger failing.
var ErrRejected = errors.New("subject token rejected")

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Upstream is one trusted token issuer and the rules that map its tokens to
// SPIFFE IDs.
type Upstream struct {
	// Name labels the upstream in logs.
	Name string
	// Issuer is the iss claim the upstream's tokens carry, compared exactly.
	Issuer string
	// Audience must be one of the subject token's audiences.
	Audience string
	// Keys supplies the upstream's verification keys.
	Keys KeySource
	// MaxTokenLifetime, when set, refuses tokens whose exp lies further than
	// this after their iat, and tokens without iat.
	MaxTokenLifetime time.Duration
	// Rules are tried in order; the first that matches decides the SPIFFE ID.
	Rules []Rule
}

// KeySource supplies an upstream's public keys.
type KeySource interface {
	// Keys returns the current key set. kid is the key the token names, so an
	// implementation can refresh when it does not know it.
	Keys(ctx context.Context, kid string) (*jose.JSONWebKeySet, error)
}

// Rule maps tokens whose claims match to a SPIFFE ID.
type Rule struct {
	// Match lists claims that must have exactly these values. A claim path
	// separates nested objects with "/", for example kubernetes.io/namespace.
	// Only string and integer claims can match.
	Match map[string]string
	// Require lists claims that must be present with a non-empty string or
	// integer value, whatever it is.
	Require []string
	// SPIFFEID is a template: each {claim/path} is replaced by that claim's
	// value, which must be a single, plain path segment.
	SPIFFEID string
}

// Exchanger verifies subject tokens against its upstreams.
type Exchanger struct {
	trustDomain spiffeid.TrustDomain
	self        string
	upstreams   map[string]Upstream
	logger      *slog.Logger
	now         func() time.Time
}

// New returns an Exchanger for the trust domain. self is the spiffex
// issuer's own URL; its tokens are never accepted as subject tokens.
func New(trustDomain spiffeid.TrustDomain, self string, upstreams []Upstream, logger *slog.Logger) (*Exchanger, error) {
	if logger == nil {
		logger = slog.Default()
	}
	e := &Exchanger{trustDomain: trustDomain, self: self, upstreams: make(map[string]Upstream), logger: logger, now: time.Now}
	for _, u := range upstreams {
		if err := e.check(u); err != nil {
			return nil, fmt.Errorf("upstream %s: %w", u.Name, err)
		}
		if _, dup := e.upstreams[u.Issuer]; dup {
			return nil, fmt.Errorf("upstream %s: issuer %s is configured twice", u.Name, u.Issuer)
		}
		e.upstreams[u.Issuer] = u
	}
	return e, nil
}

func (e *Exchanger) check(u Upstream) error {
	switch {
	case u.Issuer == "":
		return errors.New("issuer is required")
	case u.Issuer == e.self:
		return errors.New("the issuer cannot be its own upstream")
	case u.Audience == "":
		return errors.New("audience is required")
	case u.Keys == nil:
		return errors.New("a key source is required")
	case len(u.Rules) == 0:
		return errors.New("at least one rule is required")
	}
	for i, r := range u.Rules {
		if err := checkTemplate(r.SPIFFEID, e.trustDomain); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

// Exchange verifies a subject token and returns the SPIFFE ID it maps to.
// An error wrapping ErrRejected means the token is not acceptable; any other
// error means the exchanger could not decide (an upstream's keys could not be
// fetched, for one).
func (e *Exchanger) Exchange(ctx context.Context, subjectToken string) (spiffeid.ID, error) {
	token, err := jwt.ParseSigned(subjectToken, upstreamAlgorithms)
	if err != nil || len(token.Headers) != 1 {
		return spiffeid.ID{}, rejected("not a signed JWT with an accepted algorithm")
	}
	// The issuer only picks the upstream to verify against; nothing is
	// trusted until the signature checks out with that upstream's keys.
	var unverified jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return spiffeid.ID{}, rejected("malformed claims")
	}
	if unverified.Issuer == e.self {
		return spiffeid.ID{}, rejected("tokens from this issuer cannot be exchanged")
	}
	u, ok := e.upstreams[unverified.Issuer]
	if !ok {
		return spiffeid.ID{}, rejected("issuer %q is not a configured upstream", unverified.Issuer)
	}

	keys, err := u.Keys.Keys(ctx, token.Headers[0].KeyID)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("upstream %s: fetching keys: %w", u.Name, err)
	}
	var claims jwt.Claims
	if err := verifyWith(token, keys, &claims); err != nil {
		return spiffeid.ID{}, rejected("upstream %s: signature: %v", u.Name, err)
	}
	// Decoded again, now that the signature holds, keeping numbers exact.
	all, err := numberPreservingClaims(token)
	if err != nil {
		return spiffeid.ID{}, rejected("upstream %s: %v", u.Name, err)
	}
	if claims.Expiry == nil {
		return spiffeid.ID{}, rejected("upstream %s: exp is required", u.Name)
	}
	if u.MaxTokenLifetime > 0 {
		if claims.IssuedAt == nil {
			return spiffeid.ID{}, rejected("upstream %s: iat is required", u.Name)
		}
		if lifetime := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); lifetime > u.MaxTokenLifetime {
			return spiffeid.ID{}, rejected("upstream %s: token lifetime %s exceeds %s", u.Name, lifetime, u.MaxTokenLifetime)
		}
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      u.Issuer,
		AnyAudience: jwt.Audience{u.Audience},
		Time:        e.now(),
	}, clockSkew); err != nil {
		return spiffeid.ID{}, rejected("upstream %s: %v", u.Name, err)
	}

	for _, r := range u.Rules {
		if !matches(r.Match, all) || !present(r.Require, all) {
			continue
		}
		id, err := render(r.SPIFFEID, all, e.trustDomain)
		if err != nil {
			return spiffeid.ID{}, rejected("upstream %s: %v", u.Name, err)
		}
		return id, nil
	}
	return spiffeid.ID{}, rejected("upstream %s: no rule matches the token", u.Name)
}

// verifyWith checks the signature with the key the token names, or with each
// key when it names none, and decodes the claims.
func verifyWith(token *jwt.JSONWebToken, set *jose.JSONWebKeySet, out ...any) error {
	keys := set.Keys
	if kid := token.Headers[0].KeyID; kid != "" {
		keys = set.Key(kid)
	}
	if len(keys) == 0 {
		return errors.New("no matching key")
	}
	alg := token.Headers[0].Algorithm
	for _, k := range keys {
		if k.Algorithm != "" && k.Algorithm != alg {
			continue
		}
		if !k.IsPublic() {
			continue
		}
		if err := token.Claims(k.Key, out...); err == nil {
			return nil
		}
	}
	return errors.New("no key verifies the token")
}

func numberPreservingClaims(token *jwt.JSONWebToken) (map[string]any, error) {
	var raw json.RawMessage
	if err := token.UnsafeClaimsWithoutVerification(&raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var all map[string]any
	if err := dec.Decode(&all); err != nil {
		return nil, err
	}
	return all, nil
}

var integer = regexp.MustCompile(`^-?[0-9]+$`)

// claimAt returns the claim at a "/"-separated path as a string. Only strings
// and integers count; an integer is returned exactly as the token wrote it.
// Fractions, booleans, objects and lists are treated as absent, so that no
// two different values can render the same.
func claimAt(claims map[string]any, path string) (string, bool) {
	var cur any = claims
	for _, part := range strings.Split(path, "/") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = obj[part]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case json.Number:
		if integer.MatchString(v.String()) {
			return v.String(), true
		}
	}
	return "", false
}

func present(paths []string, claims map[string]any) bool {
	for _, path := range paths {
		if v, ok := claimAt(claims, path); !ok || v == "" {
			return false
		}
	}
	return true
}

func matches(want map[string]string, claims map[string]any) bool {
	for path, value := range want {
		if got, ok := claimAt(claims, path); !ok || got != value {
			return false
		}
	}
	return true
}

var (
	placeholder = regexp.MustCompile(`\{([^{}]+)\}`)
	segment     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// checkTemplate makes sure a template renders into the trust domain whatever
// the claim values, by rendering it with a harmless value.
func checkTemplate(tmpl string, td spiffeid.TrustDomain) error {
	if strings.Count(tmpl, "{") != strings.Count(tmpl, "}") {
		return fmt.Errorf("spiffe_id %q: unbalanced braces", tmpl)
	}
	sample := placeholder.ReplaceAllString(tmpl, "x")
	id, err := spiffeid.FromString(sample)
	if err != nil {
		return fmt.Errorf("spiffe_id %q: %w", tmpl, err)
	}
	if !id.MemberOf(td) {
		return fmt.Errorf("spiffe_id %q is not in trust domain %s", tmpl, td)
	}
	for _, m := range placeholder.FindAllStringIndex(tmpl, -1) {
		before, after := tmpl[:m[0]], tmpl[m[1]:]
		if !strings.HasSuffix(before, "/") || (after != "" && !strings.HasPrefix(after, "/")) {
			return fmt.Errorf("spiffe_id %q: a placeholder must fill a whole path segment", tmpl)
		}
	}
	return nil
}

// render fills a template. A claim value that is not a plain path segment is
// refused, never escaped, so that two different tokens can never map to the
// same SPIFFE ID by way of a crafted value.
func render(tmpl string, claims map[string]any, td spiffeid.TrustDomain) (spiffeid.ID, error) {
	var failure error
	out := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		path := m[1 : len(m)-1]
		v, ok := claimAt(claims, path)
		switch {
		case !ok:
			failure = fmt.Errorf("claim %s is missing, or not a string or integer", path)
		case v == "." || v == ".." || !segment.MatchString(v):
			failure = fmt.Errorf("claim %s has a value that is not a plain path segment", path)
		}
		return v
	})
	if failure != nil {
		return spiffeid.ID{}, failure
	}
	if len(out) > 2048 {
		return spiffeid.ID{}, errors.New("the SPIFFE ID would exceed 2048 bytes")
	}
	id, err := spiffeid.FromString(out)
	if err != nil {
		return spiffeid.ID{}, err
	}
	if !id.MemberOf(td) {
		return spiffeid.ID{}, fmt.Errorf("%s is not in trust domain %s", id, td)
	}
	return id, nil
}
