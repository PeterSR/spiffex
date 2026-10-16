package state

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// subjectTokenAlgorithms are the algorithms a subject token may be signed
// with: asymmetric only (SPEC section 3.3).
var subjectTokenAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// clockSkew is allowed on time comparisons with an upstream's clock, and on
// top of max_token_lifetime (SPEC section 3.3).
const clockSkew = 30 * time.Second

// Explanation tells how a subject token would fare against a state: the
// origin it reaches, whether that origin admits it and why not, and the
// SPIFFE ID it would get. It is worked out without verifying the token's
// signature. It covers jwt origins only: an exec origin's claims come from
// running its verifier, which explaining never does.
type Explanation struct {
	Issuer    string
	Audiences []string
	// Origin is the origin the token reaches by issuer and audience, if any.
	Origin   string
	Admitted bool
	// Reasons say why the token would be refused.
	Reasons []string
	// SPIFFEID is the identity the token would get, when admitted.
	SPIFFEID string
}

// Explain explains how the issuer would treat a subject token (SPEC
// section 6.3). It never verifies the signature, so it says nothing about
// whether the token is genuine. The state must be valid.
func Explain(st *State, s Settings, token string) (*Explanation, error) {
	return explainAt(st, s, token, time.Now())
}

func explainAt(st *State, s Settings, token string, now time.Time) (*Explanation, error) {
	report := Validate(st, s)
	if err := report.Err(); err != nil {
		return nil, fmt.Errorf("the state is invalid:\n%w", err)
	}
	parsed, err := jwt.ParseSigned(strings.TrimSpace(token), subjectTokenAlgorithms)
	if err != nil || len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("not a JWT signed with an asymmetric algorithm the issuer accepts")
	}
	var payload json.RawMessage
	if err := parsed.UnsafeClaimsWithoutVerification(&payload); err != nil {
		return nil, fmt.Errorf("malformed claims: %w", err)
	}
	claims, err := DecodeClaims(payload)
	if err != nil {
		return nil, err
	}
	var times jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&times); err != nil {
		return nil, fmt.Errorf("malformed claims: %w", err)
	}

	x := &Explanation{Audiences: times.Audience}
	x.Issuer, _ = claims["iss"].(string)
	refuse := func(format string, args ...any) *Explanation {
		x.Reasons = append(x.Reasons, fmt.Sprintf(format, args...))
		return x
	}
	if x.Issuer == "" {
		return refuse("the token has no iss claim"), nil
	}
	if x.Issuer == s.Issuer {
		return refuse("the token comes from this issuer, whose tokens cannot be exchanged"), nil
	}

	var reached []*Expanded
	var otherAudiences []string
	for _, name := range sortedKeys(report.Origins) {
		e := report.Origins[name]
		if e.JWT == nil || e.JWT.Issuer != x.Issuer {
			continue
		}
		if slices.Contains(x.Audiences, e.JWT.Audience) {
			reached = append(reached, e)
		} else {
			otherAudiences = append(otherAudiences, fmt.Sprintf("origin %s wants audience %s", name, e.JWT.Audience))
		}
	}
	switch len(reached) {
	case 0:
		if len(otherAudiences) > 0 {
			return refuse("no origin takes tokens from %s with these audiences (%s)", x.Issuer, strings.Join(otherAudiences, "; ")), nil
		}
		return refuse("no origin takes tokens from %s", x.Issuer), nil
	case 1:
	default:
		var names []string
		for _, e := range reached {
			names = append(names, e.Name)
		}
		return refuse("the audiences name more than one origin: %s", strings.Join(names, ", ")), nil
	}
	e := reached[0]
	x.Origin = e.Name

	switch {
	case times.Expiry == nil:
		x.Reasons = append(x.Reasons, "the token has no exp claim")
	case now.Add(-clockSkew).After(times.Expiry.Time()):
		x.Reasons = append(x.Reasons, fmt.Sprintf("the token expired at %s", times.Expiry.Time().UTC().Format(time.RFC3339)))
	}
	if times.NotBefore != nil && now.Add(clockSkew).Before(times.NotBefore.Time()) {
		x.Reasons = append(x.Reasons, fmt.Sprintf("the token is not valid before %s", times.NotBefore.Time().UTC().Format(time.RFC3339)))
	}
	switch {
	case times.IssuedAt == nil:
		x.Reasons = append(x.Reasons, "the token has no iat claim")
	case times.Expiry != nil:
		if lifetime := times.Expiry.Time().Sub(times.IssuedAt.Time()); lifetime > e.JWT.MaxTokenLifetime+clockSkew {
			x.Reasons = append(x.Reasons, fmt.Sprintf("the token was issued to live %s, longer than the %s (plus %s) origin %s accepts", lifetime, e.JWT.MaxTokenLifetime, clockSkew, e.Name))
		}
	}

	id, reasons := e.admit(s.TrustDomain, claims)
	x.Reasons = append(x.Reasons, reasons...)
	if len(x.Reasons) == 0 {
		x.Admitted = true
		x.SPIFFEID = id.String()
	}
	return x, nil
}

// String renders the explanation for people.
func (x *Explanation) String() string {
	var b strings.Builder
	fmt.Fprintln(&b, "signature: not verified; this explains the token as if it were genuine")
	fmt.Fprintf(&b, "issuer:    %s\n", x.Issuer)
	fmt.Fprintf(&b, "audiences: %s\n", strings.Join(x.Audiences, ", "))
	origin := x.Origin
	if origin == "" {
		origin = "none"
	}
	fmt.Fprintf(&b, "origin:    %s\n", origin)
	if x.Admitted {
		fmt.Fprintln(&b, "admitted:  yes")
		fmt.Fprintf(&b, "spiffe id: %s\n", x.SPIFFEID)
		return b.String()
	}
	fmt.Fprintln(&b, "admitted:  no")
	for _, r := range x.Reasons {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	return b.String()
}
