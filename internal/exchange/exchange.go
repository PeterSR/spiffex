// Package exchange verifies subject tokens from upstream issuers (a
// Kubernetes cluster, a CI provider, a cloud) against the keys of the jwt
// origin they reach, for the token exchange grant (SPEC section 3.3). It
// fetches those keys within the limits of SPEC section 5.2.
package exchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/PeterSR/spiffex/internal/state"
)

// Algorithms are the signature algorithms accepted on subject tokens:
// asymmetric only, so a public key set can never verify an HMAC.
var Algorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// ErrRejected is wrapped by every error that means the subject token is not
// acceptable, as opposed to the issuer failing to decide.
var ErrRejected = errors.New("subject token rejected")

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Token is a subject token parsed but not verified.
type Token struct {
	jws *jwt.JSONWebToken
	// Issuer and Audience are the token's claims as it states them. They
	// only choose the origin whose keys verify it.
	Issuer   string
	Audience []string
}

// Parse reads a subject token without verifying it.
func Parse(raw string) (*Token, error) {
	jws, err := jwt.ParseSigned(raw, Algorithms)
	if err != nil || len(jws.Headers) != 1 {
		return nil, rejected("not a JWT signed with an accepted algorithm")
	}
	var claims jwt.Claims
	if err := jws.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, rejected("malformed claims")
	}
	return &Token{jws: jws, Issuer: claims.Issuer, Audience: claims.Audience}, nil
}

// Verify checks the token's signature with the keys of the origin it
// reached and its times (SPEC section 3.3, steps 3 and 4), and returns its
// claims as state.DecodeClaims gives them. An error wrapping ErrRejected
// refuses the token; any other means the keys could not be had.
func (t *Token) Verify(ctx context.Context, origin *state.ExpandedJWT, keys KeySource, now time.Time) (map[string]any, error) {
	header := t.jws.Headers[0]
	set, err := keys.Keys(ctx, header.KeyID)
	if err != nil {
		return nil, fmt.Errorf("fetching the upstream's keys: %w", err)
	}
	var payload json.RawMessage
	var times jwt.Claims
	if err := verifyWith(t.jws, set, &payload, &times); err != nil {
		return nil, rejected("signature: %v", err)
	}
	if times.Issuer != origin.Issuer || !slices.Contains(times.Audience, origin.Audience) {
		return nil, rejected("the verified iss or aud does not fit the origin")
	}
	if times.Expiry == nil || times.IssuedAt == nil {
		return nil, rejected("exp and iat are required")
	}
	if lifetime := times.Expiry.Time().Sub(times.IssuedAt.Time()); !origin.AllowsLifetime(lifetime) {
		return nil, rejected("issued to live %s, longer than the %s (plus %s) the origin accepts", lifetime, origin.MaxTokenLifetime, state.ClockSkew)
	}
	if err := times.ValidateWithLeeway(jwt.Expected{Time: now}, state.ClockSkew); err != nil {
		return nil, rejected("%v", err)
	}
	claims, err := state.DecodeClaims(payload)
	if err != nil {
		return nil, rejected("%v", err)
	}
	return claims, nil
}

// verifyWith checks the signature with the key the token names, or with
// each key when it names none, and decodes the claims.
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

// UnverifiedIssuers returns the iss claims of anything shaped like a JWT,
// whatever its algorithm and without checking its signature, for refusing
// the issuer's own tokens before they go anywhere. It reads the compact
// serialization and the JSON serializations of JWS (an object with a
// payload member), with the payload in any base64 alphabet, padded or not.
// A payload may name iss more than once, and parsers disagree on which one
// counts, so every one is returned.
func UnverifiedIssuers(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var jws struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal([]byte(trimmed), &jws) != nil {
			return nil
		}
		return payloadIssuers(jws.Payload)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil
	}
	return payloadIssuers(parts[1])
}

func payloadIssuers(encoded string) []string {
	payload, ok := decodeBase64(encoded)
	if !ok {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	var issuers []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return issuers
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return issuers
		}
		var iss string
		if key == "iss" && json.Unmarshal(value, &iss) == nil {
			issuers = append(issuers, iss)
		}
	}
	return issuers
}

// decodeBase64 decodes base64 in the URL or the standard alphabet, with or
// without padding.
func decodeBase64(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if data, err := enc.DecodeString(s); err == nil {
			return data, true
		}
	}
	return nil, false
}
