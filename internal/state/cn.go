package state

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PeterSR/spiffex/internal/nametemplate"
)

// This file checks the common name templates of X.509-SVIDs (SPEC section
// 4.6). A template is one-to-one within an origin by construction. The check
// across origins works on a description of what each origin's names can look
// like, and accepts a pair only when the descriptions prove that no name can
// be in both.

// endKind says what follows the known text of a valueShape.
type endKind int

const (
	// endOpen: anything, possibly nothing.
	endOpen endKind = iota
	// endNotSlash: at least one more character, and the next is not /.
	endNotSlash
	// endExact: nothing; the known text is the whole value.
	endExact
)

// valueShape describes a set of strings: every one starts with known and
// continues as end says.
type valueShape struct {
	known string
	end   endKind
	// restPath says every character after known is one a path holds: a
	// segment character or /.
	restPath bool
}

func isPathChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-' || c == '/'
}

func allPathChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isPathChar(s[i]) {
			return false
		}
	}
	return true
}

// cnForm describes all the common names an origin can issue. Without a hash,
// a name is lead + a value described by v + tail. With one (hashN > 0), it is
// lead + hashN characters of a-z and 2-7 + tail, and v describes the value
// that was hashed.
type cnForm struct {
	lead, tail string
	v          valueShape
	hashN      int
}

// baseShape describes the placeholder's value before its operations. Every
// SPIFFE ID of an origin has the origin's prefix as a path, followed, unless
// the name template is empty, by / and a non-empty segment.
func baseShape(placeholder, td, prefix string, emptyName bool) valueShape {
	var s valueShape
	if emptyName {
		s = valueShape{prefix, endExact, false}
	} else {
		s = valueShape{strings.TrimSuffix(prefix, "/") + "/", endNotSlash, true}
	}
	if placeholder == nametemplate.CNSpiffeID {
		s.known = "spiffe://" + td + s.known
	}
	return s
}

// apply describes the result of a trim operation. dead is set when the
// operation can never apply to any value of the shape.
func (s valueShape) apply(op nametemplate.Op) (out valueShape, dead bool) {
	switch op.Name {
	case nametemplate.TrimPrefix:
		switch {
		case strings.HasPrefix(s.known, op.Arg):
			out = valueShape{s.known[len(op.Arg):], s.end, s.restPath}
			return out, out.known == "" && out.end == endExact
		case s.end != endExact && strings.HasPrefix(op.Arg, s.known):
			// The argument reaches into the part that is not known.
			return valueShape{restPath: s.restPath}, false
		}
		return valueShape{}, true
	case nametemplate.TrimSuffix:
		if s.end == endExact {
			rest, ok := strings.CutSuffix(s.known, op.Arg)
			return valueShape{rest, endExact, false}, !ok || rest == ""
		}
		// What is left is a non-empty start of the value, so it keeps the
		// first character, or the fact that it is not /.
		switch {
		case s.known != "":
			return valueShape{s.known[:1], endOpen, false}, false
		case s.end == endNotSlash:
			return valueShape{"", endNotSlash, s.restPath}, false
		}
		return valueShape{restPath: s.restPath}, false
	}
	return s, false
}

// minValue is the least length of a value of the shape, which is never empty.
func (s valueShape) minValue() int {
	n := len(s.known)
	if s.end == endNotSlash {
		n++
	}
	return max(n, 1)
}

// formOf describes the names of a template for an origin. dead is set, with
// the operation, when an operation can never apply.
func formOf(cn *nametemplate.CN, td, prefix string, emptyName bool) (f cnForm, dead *nametemplate.Op) {
	v := baseShape(cn.Placeholder, td, prefix, emptyName)
	f = cnForm{lead: cn.Lead, tail: cn.Tail}
	for i, op := range cn.Ops {
		if op.Name == nametemplate.Hash {
			f.hashN, _ = op.HashLength()
			break
		}
		var isDead bool
		if v, isDead = v.apply(op); isDead && dead == nil {
			dead = &cn.Ops[i]
		}
	}
	f.v = v
	return f, dead
}

func (f cnForm) minLen() int {
	if f.hashN > 0 {
		return len(f.lead) + f.hashN + len(f.tail)
	}
	return len(f.lead) + f.v.minValue() + len(f.tail)
}

// shape describes the names of a form without a hash as one shape.
func (f cnForm) shape() valueShape {
	if f.v.end == endExact {
		return valueShape{f.lead + f.v.known + f.tail, endExact, false}
	}
	return valueShape{f.lead + f.v.known, f.v.end, f.v.restPath && allPathChars(f.tail)}
}

// shapesDisjoint reports whether no string is in both shapes.
func shapesDisjoint(a, b valueShape) bool {
	m := min(len(a.known), len(b.known))
	if a.known[:m] != b.known[:m] {
		return true
	}
	if len(a.known) > len(b.known) {
		a, b = b, a
	}
	if len(a.known) == len(b.known) {
		return a.end == endExact && b.end == endNotSlash || a.end == endNotSlash && b.end == endExact
	}
	switch a.end {
	case endExact:
		return true
	case endNotSlash:
		if b.known[len(a.known)] == '/' {
			return true
		}
	}
	return a.restPath && !allPathChars(b.known[len(a.known):])
}

func isBase32Char(c byte) bool { return 'a' <= c && c <= 'z' || '2' <= c && c <= '7' }

// cnDisjoint reports whether no name can be issued under both forms. Two
// different hash inputs give the same hash only by a collision of a truncated
// SHA-256 (at least 80 bits), which this treats as impossible, as it does
// within an origin.
func cnDisjoint(a, b cnForm) bool {
	switch {
	case a.hashN == 0 && b.hashN == 0:
		return shapesDisjoint(a.shape(), b.shape())
	case a.hashN > 0 && b.hashN > 0:
		if a.hashN == b.hashN && a.lead == b.lead && a.tail == b.tail {
			return shapesDisjoint(a.v, b.v)
		}
		return a.minLen() != b.minLen() ||
			!strings.HasPrefix(a.lead, b.lead) && !strings.HasPrefix(b.lead, a.lead) ||
			!strings.HasSuffix(a.tail, b.tail) && !strings.HasSuffix(b.tail, a.tail)
	case a.hashN > 0:
		return hashedVsPlain(a, b)
	}
	return hashedVsPlain(b, a)
}

func hashedVsPlain(h, p cnForm) bool {
	s := p.shape()
	if s.end == endExact && len(s.known) != h.minLen() {
		return true
	}
	if len(s.known) <= len(h.lead) {
		return !strings.HasPrefix(h.lead, s.known)
	}
	if s.known[:len(h.lead)] != h.lead {
		return true
	}
	rest := s.known[len(h.lead):]
	for i := 0; i < len(rest) && i < h.hashN; i++ {
		if !isBase32Char(rest[i]) {
			return true
		}
	}
	return false
}

// expandCN works out the origin's common name template: its own, else the
// provider's default, else none. emptyName says the name template is empty,
// so that an identity is its prefix alone.
func (x *expansion) expandCN(e *Expanded, o *Origin, p *Provider, emptyName bool) {
	text, own := p.X509.cn(), false
	if o.X509.cn() != nil {
		text, own = o.X509.cn(), true
	}
	e.X509CNOwn = own
	report := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if own {
			x.originProblem(field(field(x.path, "x509"), "cn"), "%s", msg)
			return
		}
		x.providerProblem([]string{"x509", "cn"}, fmt.Errorf("%s", msg))
	}
	td := x.v.settings.TrustDomain.Name()
	if text == nil {
		// The default names an identity by its SPIFFE ID, or by nothing
		// when that is too long.
		f, _ := formOf(&nametemplate.CN{Placeholder: nametemplate.CNSpiffeID}, td, e.Prefix, emptyName)
		if f.minLen() <= nametemplate.MaxCNLength {
			e.cn = &f
		}
		return
	}
	cn, err := nametemplate.ParseCN(*text)
	if err != nil {
		report("%v", err)
		return
	}
	e.X509CN = cn
	f, dead := formOf(cn, td, e.Prefix, emptyName)
	if x.synthetic {
		// Checked as if by an origin that is not there: the prefix is made up.
		return
	}
	switch {
	case dead != nil:
		report("origin %s: %s can never apply to its identities, which all have a path starting with %s", x.name, dead, e.Prefix)
	case f.minLen() > nametemplate.MaxCNLength:
		report("origin %s: its common names are at least %d characters, more than the %d allowed", x.name, f.minLen(), nametemplate.MaxCNLength)
	default:
		e.cn = &f
	}
}

// CommonName returns the common name of the X.509-SVID of a SPIFFE ID, given
// as its full URI and its path, or "" for none. Without a template the name is
// the SPIFFE ID when it fits in 64 characters and none otherwise. With one
// it is the template's, and an error when the template cannot name this
// identity.
func (e *Expanded) CommonName(spiffeID, path string) (string, error) {
	if e.X509CN == nil {
		if len(spiffeID) > nametemplate.MaxCNLength {
			return "", nil
		}
		return spiffeID, nil
	}
	return e.X509CN.Render(spiffeID, path)
}

// X509CNUnused names the origins that set x509.cn themselves but do not list
// x509 in svid_types, sorted.
func (r *Report) X509CNUnused() []string {
	var names []string
	for name, e := range r.Origins {
		if e.X509CNOwn && !e.AllowsSVIDType("x509") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// checkCommonNames refuses two origins whose X.509-SVIDs could have the same
// common name (SPEC section 4.6), so that a data store matching on it cannot
// confuse the identities of two origins.
func (v *validator) checkCommonNames(origins map[string]*Expanded) {
	names := sortedKeys(origins)
	for i, a := range names {
		ea := origins[a]
		if ea.cn == nil || !ea.AllowsSVIDType("x509") {
			continue
		}
		for _, b := range names[i+1:] {
			eb := origins[b]
			if eb.cn == nil || !eb.AllowsSVIDType("x509") {
				continue
			}
			// Overlapping prefixes are a problem of their own, and the
			// proof below relies on them not overlapping.
			if overlap(ea.Prefix, eb.Prefix) {
				continue
			}
			if !cnDisjoint(*ea.cn, *eb.cn) {
				v.add(field("origins", b), "its X.509 common names could equal those of origin %s (x509.cn %s and %s); begin each template with text that differs between the origins, or leave x509.cn out", a, ea.cnText(), eb.cnText())
			}
		}
	}
}

func (e *Expanded) cnText() string {
	if e.X509CN == nil {
		return "{spiffe_id}"
	}
	return e.X509CN.String()
}
