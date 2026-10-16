package state

import (
	"fmt"
	"slices"
)

// The permissions a grant can give (SPEC section 8.2).
const (
	PermRead     = "read"
	PermWrite    = "write"
	PermDelegate = "delegate"
)

// ParsedGrant is a grant whose who is parsed.
type ParsedGrant struct {
	Name string
	Who  IDPattern
	Can  []string
	On   []string
}

// Holds reports whether the grant gives permission perm on path, with read
// implied by write and delegate. A path that is not canonical is never held.
func (g ParsedGrant) Holds(perm, path string) bool {
	implied := perm == PermRead && (slices.Contains(g.Can, PermWrite) || slices.Contains(g.Can, PermDelegate))
	if !implied && !slices.Contains(g.Can, perm) {
		return false
	}
	return g.on(path)
}

func (g ParsedGrant) on(path string) bool {
	for _, scope := range g.On {
		if within(path, scope) {
			return true
		}
	}
	return false
}

// checkGrants checks each grant on its own and returns them parsed, or nil
// when any is invalid.
func (v *validator) checkGrants() []ParsedGrant {
	var out []ParsedGrant
	ok := true
	for _, name := range sortedKeys(v.state.Grants) {
		path := field("grants", name)
		g := v.state.Grants[name]
		start := v.count()
		if err := checkName(name); err != nil {
			v.add(path, "%v", err)
		}
		who, err := ParseIDPattern(g.Who, v.settings.TrustDomain)
		if err != nil {
			v.add(field(path, "who"), "%v", err)
		}
		if len(g.Can) == 0 {
			v.add(field(path, "can"), "give at least one permission")
		}
		for i, perm := range g.Can {
			switch {
			case perm != PermRead && perm != PermWrite && perm != PermDelegate:
				v.add(index(field(path, "can"), i), "want read, write or delegate, not %q", perm)
			case slices.Index(g.Can, perm) != i:
				v.add(index(field(path, "can"), i), "%s is listed twice", perm)
			}
		}
		if len(g.On) == 0 {
			v.add(field(path, "on"), "give at least one scope")
		}
		for i, scope := range g.On {
			if err := checkPrefix(scope); err != nil {
				v.add(index(field(path, "on"), i), "%v", err)
			} else if slices.Index(g.On, scope) != i {
				v.add(index(field(path, "on"), i), "%s is listed twice", scope)
			}
		}
		if v.count() > start {
			ok = false
			continue
		}
		out = append(out, ParsedGrant{Name: name, Who: who, Can: g.Can, On: g.On})
	}
	if !ok {
		return nil
	}
	return out
}

// checkClosure enforces the closure rule of SPEC section 8.2, decided
// exactly as the specification says: whenever a grant A gives write on a
// scope S that reaches the who of a grant B, a single grant whose who covers
// A's must give each permission of B on each of B's scopes. Otherwise
// writing under S would be a way to become B's subject without holding what
// B gives.
func (v *validator) checkClosure(grants []ParsedGrant) {
	for _, a := range grants {
		if !slices.Contains(a.Can, PermWrite) {
			continue
		}
		for _, b := range grants {
			i := slices.IndexFunc(a.On, func(s string) bool { return Reaches(s, b.Who) })
			if i < 0 {
				continue
			}
			for _, perm := range b.Can {
				for _, scope := range b.On {
					if !coveredBySingleGrant(grants, a.Who, perm, scope) {
						v.add(field("grants", a.Name), "%s", closureMessage(a, b, a.On[i], perm, scope))
					}
				}
			}
		}
	}
}

func coveredBySingleGrant(grants []ParsedGrant, who IDPattern, perm, scope string) bool {
	for _, g := range grants {
		if g.Who.Covers(who) && g.Holds(perm, scope) {
			return true
		}
	}
	return false
}

func closureMessage(a, b ParsedGrant, s, perm, scope string) string {
	if a.Name == b.Name {
		return fmt.Sprintf("gives write on %s, which reaches its own who %s, but no single grant gives every identity matching %s %s on %s",
			s, b.Who, a.Who, perm, scope)
	}
	return fmt.Sprintf("gives write on %s, which reaches %s, the who of grant %s; grant %s gives %s on %s, but no single grant gives every identity matching %s %s on %s",
		s, b.Who, b.Name, b.Name, perm, scope, a.Who, perm, scope)
}
