package state

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Admit decides whether a jwt or exec origin admits a verified proof, given
// the claims of the subject token or of the verifier as DecodeClaims returns
// them (SPEC section 4.3), and returns the SPIFFE ID it names. A refusal is a
// *RefusedError.
func (e *Expanded) Admit(td spiffeid.TrustDomain, claims map[string]any) (spiffeid.ID, error) {
	id, reasons := e.admit(td, claims)
	if len(reasons) > 0 {
		return spiffeid.ID{}, &RefusedError{reasons: reasons}
	}
	return id, nil
}

// RefusedError is an origin's refusal of a proof. Its message is the same
// for every refusal, so it is safe to show a token client. The reasons
// name claim values and the origin's patterns, which are for logs only:
// a client must not learn from them what the origin would admit.
type RefusedError struct {
	reasons []string
}

func (e *RefusedError) Error() string { return "the origin does not admit this proof" }

// LogDetail returns every reason for the refusal, for the issuer's log.
// Never send it to the client.
func (e *RefusedError) LogDetail() string { return strings.Join(e.reasons, "; ") }

func (e *Expanded) admit(td spiffeid.TrustDomain, claims map[string]any) (spiffeid.ID, []string) {
	if e.Kind == KindKeys {
		return spiffeid.ID{}, []string{fmt.Sprintf("origin %s takes keys, not tokens", e.Name)}
	}
	var reasons []string
	for _, path := range e.Require {
		// An empty string counts as no value: a claim that is required but
		// empty identifies nothing.
		if v, ok := ClaimValue(claims, path); !ok || v == "" {
			reasons = append(reasons, fmt.Sprintf("claim %s is required but has no value", path))
		}
	}
	for _, c := range e.Match {
		v, ok := ClaimValue(claims, c.Claim)
		switch {
		case !ok:
			reasons = append(reasons, fmt.Sprintf("match on %s: the claim has no value", c.Claim))
		case !matchAny(c.Patterns, v):
			reasons = append(reasons, fmt.Sprintf("match on %s: %q matches none of %s", c.Claim, v, quotePatterns(c.Patterns)))
		}
	}
	for _, c := range e.Deny {
		if v, ok := ClaimValue(claims, c.Claim); ok && matchAny(c.Patterns, v) {
			reasons = append(reasons, fmt.Sprintf("deny on %s: %q matches one of %s", c.Claim, v, quotePatterns(c.Patterns)))
		}
	}
	name, nameReasons := renderName(e.Template, func(path string) (string, bool) { return ClaimValue(claims, path) })
	reasons = append(reasons, nameReasons...)
	if len(reasons) > 0 {
		return spiffeid.ID{}, reasons
	}
	id, err := e.id(td, name)
	if err != nil {
		return spiffeid.ID{}, []string{err.Error()}
	}
	return id, nil
}

// MemberID returns the SPIFFE ID of a keys origin's member.
func (e *Expanded) MemberID(td spiffeid.TrustDomain, member string) (spiffeid.ID, error) {
	if _, ok := e.Members[member]; !ok {
		return spiffeid.ID{}, fmt.Errorf("origin %s has no member %s", e.Name, member)
	}
	name, reasons := renderName(e.Template, func(string) (string, bool) { return member, true })
	if len(reasons) > 0 {
		return spiffeid.ID{}, errors.New(strings.Join(reasons, "; "))
	}
	return e.id(td, name)
}

// AllowsAudience reports whether identities of the origin may request aud
// (SPEC section 4.4).
func (e *Expanded) AllowsAudience(aud string) bool {
	return e.Audiences == nil || matchAny(e.Audiences, aud)
}

func (e *Expanded) id(td spiffeid.TrustDomain, name string) (spiffeid.ID, error) {
	s := e.join(td.Name(), name)
	if len(s) > maxIDLength {
		return spiffeid.ID{}, fmt.Errorf("the SPIFFE ID would be %d bytes, more than the %d allowed", len(s), maxIDLength)
	}
	return spiffeid.FromString(s)
}

func quotePatterns(patterns []Pattern) string {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = fmt.Sprintf("%q", string(p))
	}
	return strings.Join(quoted, ", ")
}
