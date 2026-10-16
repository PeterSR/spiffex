package state

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// The permissions a grant can give (SPEC section 8.2).
const (
	PermRead     = "read"
	PermWrite    = "write"
	PermDelegate = "delegate"
)

// Limits on grants (SPEC section 6.1), which keep the closure check cheap.
const (
	MaxGrants         = 256
	MaxScopesPerGrant = 16
)

// ParsedGrant is a grant whose who is parsed.
type ParsedGrant struct {
	Name string
	Who  IDPattern
	Can  []string
	On   []string
	// scopes are the segments of On, split once.
	scopes [][]string
}

// gives reports whether the grant gives perm, with read implied by write
// and delegate.
func (g ParsedGrant) gives(perm string) bool {
	if perm == PermRead && len(g.Can) > 0 {
		return true
	}
	return slices.Contains(g.Can, perm)
}

func (g ParsedGrant) scopeSegments() [][]string {
	if g.scopes != nil || len(g.On) == 0 {
		return g.scopes
	}
	out := make([][]string, len(g.On))
	for i, scope := range g.On {
		out[i] = splitPath(scope)
	}
	return out
}

// Holds reports whether the grant gives permission perm on path, with read
// implied by write and delegate. A path that is not canonical is never held.
func (g ParsedGrant) Holds(perm, path string) bool {
	if !g.gives(perm) || checkPrefix(path) != nil {
		return false
	}
	return g.on(splitPath(path))
}

func (g ParsedGrant) on(path []string) bool {
	for _, scope := range g.scopeSegments() {
		if withinSegments(path, scope) {
			return true
		}
	}
	return false
}

// Holds reports whether a grant whose who matches id gives permission perm
// on path (SPEC section 8.2).
func Holds(grants []ParsedGrant, id spiffeid.ID, perm, path string) bool {
	if checkPrefix(path) != nil {
		return false
	}
	segs := splitPath(path)
	for _, g := range grants {
		if g.gives(perm) && g.Who.Match(id) && g.on(segs) {
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
		if len(g.On) > MaxScopesPerGrant {
			v.add(field(path, "on"), "a grant has at most %d scopes, not %d", MaxScopesPerGrant, len(g.On))
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
		pg := ParsedGrant{Name: name, Who: who, Can: g.Can, On: g.On}
		pg.scopes = pg.scopeSegments()
		out = append(out, pg)
	}
	if len(v.state.Grants) > MaxGrants {
		v.add("grants", "a state has at most %d grants, not %d", MaxGrants, len(v.state.Grants))
		ok = false
	}
	if !ok {
		return nil
	}
	return out
}

// maxClosureProblems bounds the closure gaps reported one by one; the rest
// are counted.
const maxClosureProblems = 64

// checkClosure enforces the closure rule of SPEC section 8.2, decided
// exactly as the specification says: whenever a grant A gives write on a
// scope S that reaches the who of a grant B, a single grant whose who covers
// A's must give each permission of B on each of B's scopes. Otherwise
// writing under S would be a way to become B's subject without holding what
// B gives.
//
// For each writer A, the scopes on which grants covering A's who give each
// permission are marked once; whether B's scope s is held is then a lookup
// of s and its ancestors among the marks. That keeps the whole check near
// the number of grant pairs times their scopes.
func (v *validator) checkClosure(grants []ParsedGrant) {
	idx := newScopeIndex(grants)
	perms := []string{PermRead, PermWrite, PermDelegate}
	var marks [3][]uint32
	for p := range marks {
		marks[p] = make([]uint32, len(idx.ancestors))
	}
	reported, more := 0, 0
	for ai, a := range grants {
		if !slices.Contains(a.Can, PermWrite) {
			continue
		}
		mark := uint32(ai + 1)
		for gi, g := range grants {
			if !g.Who.Covers(a.Who) {
				continue
			}
			for p, perm := range perms {
				if g.gives(perm) {
					for _, sid := range idx.scopes[gi] {
						marks[p][sid] = mark
					}
				}
			}
		}
		for bi, b := range grants {
			i := slices.IndexFunc(a.scopes, func(s []string) bool { return reachesSegments(s, b.Who) })
			if i < 0 {
				continue
			}
			for _, perm := range b.Can {
				p := slices.Index(perms, perm)
				for j, sid := range idx.scopes[bi] {
					if idx.marked(marks[p], sid, mark) {
						continue
					}
					if reported == maxClosureProblems {
						more++
						continue
					}
					reported++
					v.addProblem(Problem{
						Path:    field("grants", a.Name),
						Message: closureMessage(a, b, a.On[i], perm, b.On[j]),
						Closure: &ClosureGap{Writer: a.Name, Scope: a.On[i], Reached: b.Name, Perm: perm, On: b.On[j]},
					})
				}
			}
		}
	}
	if more > 0 {
		v.add("grants", "and %d more ways in which the grants are not closed", more)
	}
}

// scopeIndex numbers every scope of every grant, and every ancestor of
// those scopes, so that scopes can be compared as small integers.
type scopeIndex struct {
	// scopes holds, for each grant, the numbers of its scopes.
	scopes [][]int
	// ancestors holds, for each number, the numbers of the scope itself
	// and of every scope it is within.
	ancestors [][]int
}

func newScopeIndex(grants []ParsedGrant) *scopeIndex {
	idx := &scopeIndex{scopes: make([][]int, len(grants))}
	ids := map[string]int{}
	intern := func(segs []string) int {
		key := strings.Join(segs, "/")
		if id, ok := ids[key]; ok {
			return id
		}
		id := len(idx.ancestors)
		ids[key] = id
		idx.ancestors = append(idx.ancestors, nil)
		return id
	}
	for gi, g := range grants {
		for _, segs := range g.scopes {
			id := intern(segs)
			if idx.ancestors[id] == nil {
				chain := make([]int, 0, len(segs)+1)
				for k := 0; k <= len(segs); k++ {
					chain = append(chain, intern(segs[:k]))
				}
				idx.ancestors[id] = chain
			}
			idx.scopes[gi] = append(idx.scopes[gi], id)
		}
	}
	return idx
}

// marked reports whether scope id, or a scope it is within, carries mark.
func (idx *scopeIndex) marked(marks []uint32, id int, mark uint32) bool {
	for _, a := range idx.ancestors[id] {
		if marks[a] == mark {
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
