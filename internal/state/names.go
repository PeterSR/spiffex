package state

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	paramNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	segmentRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
)

// checkName checks the name of an origin, provider or grant.
func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("name %q must be 1 to 63 characters from a-z, 0-9 and -, starting with a letter", name)
	}
	return nil
}

// validSegment reports whether s may be one segment of a SPIFFE ID path.
func validSegment(s string) bool {
	return s != "." && s != ".." && segmentRE.MatchString(s)
}

func checkSegment(s string) error {
	if !validSegment(s) {
		return fmt.Errorf("%q is not a path segment: want 1 to 255 characters from A-Z, a-z, 0-9, ., _ and -, other than . and .. alone", s)
	}
	return nil
}

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

// overlap reports whether two prefixes overlap (SPEC section 4.1).
func overlap(a, b string) bool {
	return within(a, b) || within(b, a)
}
