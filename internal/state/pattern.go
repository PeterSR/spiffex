package state

import "strings"

// Pattern is literal text in which * stands for any run of characters,
// including none (SPEC section 4.3). It matches whole values only.
type Pattern string

// Exact reports whether the pattern has no *.
func (p Pattern) Exact() bool {
	return !strings.Contains(string(p), "*")
}

// Match reports whether the pattern matches all of v. It runs in time linear
// in the lengths of p and v: after the fixed first and last pieces, taking the
// leftmost occurrence of each middle piece is never worse than any other
// choice, so no backtracking is needed.
func (p Pattern) Match(v string) bool {
	pieces := strings.Split(string(p), "*")
	if len(pieces) == 1 {
		return string(p) == v
	}
	first, last := pieces[0], pieces[len(pieces)-1]
	if len(v) < len(first)+len(last) || !strings.HasPrefix(v, first) || !strings.HasSuffix(v, last) {
		return false
	}
	rest := v[len(first) : len(v)-len(last)]
	for _, piece := range pieces[1 : len(pieces)-1] {
		i := strings.Index(rest, piece)
		if i < 0 {
			return false
		}
		rest = rest[i+len(piece):]
	}
	return true
}

func matchAny(patterns []Pattern, v string) bool {
	for _, p := range patterns {
		if p.Match(v) {
			return true
		}
	}
	return false
}

func toPatterns(values []string) []Pattern {
	out := make([]Pattern, len(values))
	for i, v := range values {
		out[i] = Pattern(v)
	}
	return out
}
