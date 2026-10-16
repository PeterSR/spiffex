package state

import (
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// IDPattern is a SPIFFE ID pattern (SPEC section 8.2): a SPIFFE ID in the
// trust domain whose path segments may be *, matching any one segment, and
// whose last segment may be **, matching one or more. The zero IDPattern
// matches, reaches and covers nothing.
type IDPattern struct {
	text     string
	segments []string
}

// ParseIDPattern parses a SPIFFE ID pattern in the trust domain td.
func ParseIDPattern(s string, td spiffeid.TrustDomain) (IDPattern, error) {
	rest, ok := strings.CutPrefix(s, "spiffe://")
	if !ok {
		return IDPattern{}, fmt.Errorf("%q must start with spiffe://", s)
	}
	host, path, _ := strings.Cut(rest, "/")
	if host != td.Name() {
		return IDPattern{}, fmt.Errorf("%q is not in trust domain %s", s, td.Name())
	}
	if path == "" {
		return IDPattern{}, fmt.Errorf("%q has no path", s)
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		switch {
		case seg == "*":
		case seg == "**":
			if i != len(segments)-1 {
				return IDPattern{}, fmt.Errorf("%q: ** can only be the last segment", s)
			}
		default:
			if err := checkSegment(seg); err != nil {
				return IDPattern{}, fmt.Errorf("%q: %w", s, err)
			}
		}
	}
	return IDPattern{text: s, segments: segments}, nil
}

// String returns the pattern as written.
func (p IDPattern) String() string { return p.text }

// LiteralPrefix returns the path before the first * or ** segment, or /
// when the pattern starts with one.
func (p IDPattern) LiteralPrefix() string {
	var lit []string
	for _, seg := range p.segments {
		if seg == "*" || seg == "**" {
			break
		}
		lit = append(lit, seg)
	}
	return "/" + strings.Join(lit, "/")
}

// Match reports whether id matches the pattern.
func (p IDPattern) Match(id spiffeid.ID) bool {
	if p.text == "" || !strings.HasPrefix(p.text, "spiffe://"+id.TrustDomain().Name()+"/") {
		return false
	}
	return p.MatchPath(id.Path())
}

// MatchPath reports whether a SPIFFE ID path, such as /vms/billing, matches
// the pattern.
func (p IDPattern) MatchPath(path string) bool {
	if len(p.segments) == 0 || checkPrefix(path) != nil {
		return false
	}
	segs := splitPath(path)
	for i, pat := range p.segments {
		if pat == "**" {
			return len(segs) > i
		}
		if i >= len(segs) || pat != "*" && pat != segs[i] {
			return false
		}
	}
	return len(segs) == len(p.segments)
}

// Reaches reports whether some path within scope matches w (SPEC
// section 8.2).
func Reaches(scope string, w IDPattern) bool {
	if len(w.segments) == 0 || checkPrefix(scope) != nil {
		return false
	}
	s := splitPath(scope)
	for i := 0; i < len(s) && i < len(w.segments); i++ {
		switch w.segments[i] {
		case "**":
			return true
		case "*":
		default:
			if w.segments[i] != s[i] {
				return false
			}
		}
	}
	// Both ran out together, or the scope ran out first and its extensions
	// can supply the rest; when the pattern runs out first, every path
	// within the scope is too long for it.
	return len(s) <= len(w.segments)
}

// Covers reports whether every SPIFFE ID matching q matches p (SPEC
// section 8.2).
func (p IDPattern) Covers(q IDPattern) bool {
	ps, qs := p.segments, q.segments
	if len(ps) == 0 || len(qs) == 0 {
		return false
	}
	k := len(ps)
	if k > 0 && ps[k-1] == "**" {
		k--
		if len(qs) <= k {
			return false
		}
	} else if len(qs) != len(ps) || qs[len(qs)-1] == "**" {
		return false
	}
	for i := 0; i < k; i++ {
		if qs[i] == "**" {
			return false
		}
		if ps[i] != "*" && (qs[i] == "*" || ps[i] != qs[i]) {
			return false
		}
	}
	return true
}
