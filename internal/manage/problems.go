package manage

import (
	"strings"

	"github.com/PeterSR/spiffex/internal/state"
)

// visibleProblems rewrites the problems of a proposed state so they say
// nothing about objects the caller may not read, beyond the names and
// prefixes of origins and the upstream issuer and audience of jwt origins,
// which are not secret (SPEC sections 4 and 8.3). own is the object being
// written, as section.name, which the caller has just sent and so may see.
func (b *base) visibleProblems(c caller, own string, ps state.Problems) state.Problems {
	var out state.Problems
	seen := map[string]bool{}
	add := func(p state.Problem) {
		if !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p)
		}
	}
	for _, p := range ps {
		if p.Closure != nil {
			add(b.closureProblem(c, own, p))
			continue
		}
		section, name := objectOf(p.Path)
		switch {
		case section+"."+name == own:
			add(p)
		case section == "origins" && b.state.Origins[name] != nil && !b.readsOrigin(c, name):
			// Base was valid, and conflicts with unreadable origins are
			// answered with 409 before validation, so this is unexpected;
			// the name alone is not secret.
			add(state.Problem{Path: "origins." + name, Message: "has a problem in a part you may not read"})
		case section == "grants" && b.state.Grants[name] != nil && !b.readsGrant(c, name):
			add(state.Problem{Path: "grants", Message: "a grant you may not read has a problem"})
		default:
			add(p)
		}
	}
	return out
}

// hiddenClosure is the one reason given for a closure gap involving a
// grant the caller may not read. It says neither which grant that is, nor
// whether it is the one writing or the one reached, nor its scopes.
var hiddenClosure = state.Problem{
	Path:    "grants",
	Message: "the grants would not be closed, through a grant you may not read",
}

// closureProblem names the grants of a closure gap and the missing
// permission (SPEC section 8.2) when the caller may read both grants, and
// otherwise says only that a grant it may not read is involved.
func (b *base) closureProblem(c caller, own string, p state.Problem) state.Problem {
	gap := p.Closure
	reads := func(name string) bool { return "grants."+name == own || b.readsGrant(c, name) }
	if reads(gap.Writer) && reads(gap.Reached) {
		return p
	}
	return hiddenClosure
}

// objectOf splits a problem path such as origins.web.with.namespaces into
// its section and object name. Names of origins, providers and grants never
// need quoting, so the first two parts are always plain.
func objectOf(path string) (section, name string) {
	section, rest, _ := strings.Cut(path, ".")
	name, _, _ = strings.Cut(rest, ".")
	name, _, _ = strings.Cut(name, "[")
	return section, name
}
