package state

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/PeterSR/spiffex/internal/nametemplate"
)

var (
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	paramNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

// checkName checks the name of an origin, provider or grant.
func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("name %q must be 1 to 63 characters from a-z, 0-9 and -, starting with a letter", name)
	}
	return nil
}

// ValidName reports whether s may name an origin, provider or grant.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidSegment reports whether s may be one segment of a SPIFFE ID path,
// such as a member's name.
func ValidSegment(s string) bool { return validSegment(s) }

func validSegment(s string) bool { return nametemplate.ValidSegment(s) }

func checkSegment(s string) error { return nametemplate.CheckSegment(s) }

// splitPath splits a prefix or scope into its segments; / has none.
func splitPath(p string) []string {
	if p == "/" || p == "" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// checkPrefix checks a prefix or scope: / or one or more /<segment>.
func checkPrefix(p string) error {
	if p == "/" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%q must start with /", p)
	}
	for _, seg := range splitPath(p) {
		if err := checkSegment(seg); err != nil {
			return fmt.Errorf("%q: %w", p, err)
		}
	}
	return nil
}

// within reports whether path equals scope or extends it by whole segments.
// Both must be canonical: /vms/../admin is within nothing, whatever it may
// look like.
func within(path, scope string) bool {
	if checkPrefix(path) != nil || checkPrefix(scope) != nil {
		return false
	}
	if scope == "/" || path == scope {
		return true
	}
	return strings.HasPrefix(path, scope+"/")
}

// withinSegments is within for paths already split into valid segments.
func withinSegments(path, scope []string) bool {
	return len(path) >= len(scope) && slices.Equal(path[:len(scope)], scope)
}

// overlap reports whether two prefixes overlap (SPEC section 4.1).
func overlap(a, b string) bool {
	return within(a, b) || within(b, a)
}

// Overlap reports whether two prefixes overlap: one equals the other or
// extends it by whole segments (SPEC section 4.1).
func Overlap(a, b string) bool { return overlap(a, b) }
