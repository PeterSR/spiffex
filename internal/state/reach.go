package state

import (
	"slices"
	"time"
)

// ClockSkew is allowed on every time comparison with an upstream's clock,
// and on top of max_token_lifetime (SPEC section 3.3).
const ClockSkew = 30 * time.Second

// Reached returns the jwt origins a subject token reaches by its unverified
// iss and aud claims: those whose upstream issuer equals iss exactly and
// whose audience is among auds (SPEC section 3.3). A valid state has at most
// one per token, but a caller must still refuse a token that reaches several.
func Reached(origins map[string]*Expanded, iss string, auds []string) []*Expanded {
	var out []*Expanded
	for _, name := range sortedKeys(origins) {
		e := origins[name]
		if e.JWT != nil && e.JWT.Issuer == iss && slices.Contains(auds, e.JWT.Audience) {
			out = append(out, e)
		}
	}
	return out
}

// AllowsLifetime reports whether a subject token issued to live for d, its
// exp minus its iat, is acceptable: no longer than max_token_lifetime plus
// the clock skew allowance.
func (j *ExpandedJWT) AllowsLifetime(d time.Duration) bool {
	return d <= j.MaxTokenLifetime+ClockSkew
}
