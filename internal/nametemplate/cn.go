package nametemplate

import (
	"fmt"
	"strings"
)

// The placeholders of a common name template. Both are derived from the issued
// SPIFFE ID alone, never from the subject token's claims, so a common name
// identifies exactly one SPIFFE ID.
const (
	// CNSpiffeID is the full SPIFFE ID, spiffe://<trust domain><path>.
	CNSpiffeID = "spiffe_id"
	// CNPath is the path of the SPIFFE ID, starting with /.
	CNPath = "path"
)

// MaxCNLength is the upper bound RFC 5280 sets on a common name.
const MaxCNLength = 64

// maxCNArg bounds the argument of a trim operation in a common name template.
const maxCNArg = MaxCNLength

// CN is a parsed common name template: literal text around exactly one
// placeholder, which may pass its value through operations first.
//
//	{path}
//	{path|trim_prefix:/tenants/}
//	pg-{path|hash:24}
//
// Make one with ParseCN: a CN built by hand is not validated.
type CN struct {
	// Lead and Tail are the literal text before and after the placeholder.
	Lead, Tail string
	// Placeholder is CNSpiffeID or CNPath.
	Placeholder string
	// Ops are applied to the placeholder's value in order. A hash, if there
	// is one, is the last.
	Ops []Op
}

// cnLiteral reports whether c may appear in the literal text of a common name
// template or in the argument of one of its trim operations: the characters of
// a path segment, plus / and :. They are printable ASCII that is valid in a
// PrintableString and in a UTF8String, and none of them is special in a
// distinguished name's string form (RFC 4514). A leading / is special to
// PostgreSQL, which reads a pg_ident.conf system user that starts with one as
// a regular expression, so a name never starts with it (see ParseCN, Render).
func cnLiteral(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '.' || c == '_' || c == '-' || c == '/' || c == ':'
}

func cnText(s string) bool {
	for i := 0; i < len(s); i++ {
		if !cnLiteral(s[i]) {
			return false
		}
	}
	return true
}

// ParseCN parses a common name template. It has exactly one placeholder, so
// a template with none (which would give every identity the same name) is
// refused, and the literal text is limited to the characters of cnLiteral.
func ParseCN(s string) (*CN, error) {
	open := strings.IndexByte(s, '{')
	if open < 0 {
		return nil, fmt.Errorf("common name template %q: it needs a placeholder, {%s} or {%s}", s, CNSpiffeID, CNPath)
	}
	end := strings.IndexByte(s, '}')
	if end < open {
		return nil, fmt.Errorf("common name template %q: unclosed {", s)
	}
	cn := &CN{Lead: s[:open], Tail: s[end+1:]}
	if strings.HasPrefix(cn.Lead, "/") {
		return nil, fmt.Errorf("common name template %q: the name must not start with /, which PostgreSQL reads as a regular expression in pg_ident.conf; start with text, or trim the leading / with trim_prefix", s)
	}
	inner := s[open+1 : end]
	if strings.Contains(inner, "{") || strings.ContainsAny(cn.Tail, "{}") {
		return nil, fmt.Errorf("common name template %q: it has exactly one placeholder", s)
	}
	for _, lit := range []string{cn.Lead, cn.Tail} {
		if !cnText(lit) {
			return nil, fmt.Errorf("common name template %q: the text around the placeholder may use only A-Z, a-z, 0-9, ., _, -, / and the colon", s)
		}
	}
	name, opsText, hasOps := strings.Cut(inner, "|")
	if name != CNSpiffeID && name != CNPath {
		return nil, fmt.Errorf("common name template %q: the placeholder is {%s} or {%s}, not {%s}", s, CNSpiffeID, CNPath, name)
	}
	cn.Placeholder = name
	if hasOps {
		for i, opText := range strings.Split(opsText, "|") {
			op, err := parseCNOp(opText)
			if err != nil {
				return nil, fmt.Errorf("common name template %q: %w", s, err)
			}
			if op.Name == Hash && i != strings.Count(opsText, "|") {
				return nil, fmt.Errorf("common name template %q: %s must be the last operation", s, Hash)
			}
			cn.Ops = append(cn.Ops, op)
		}
	}
	if len(cn.Lead)+len(cn.Tail) >= MaxCNLength {
		return nil, fmt.Errorf("common name template %q: its text alone leaves no room for the placeholder in %d characters", s, MaxCNLength)
	}
	return cn, nil
}

func parseCNOp(s string) (Op, error) {
	name, arg, ok := strings.Cut(s, ":")
	if !ok {
		return Op{}, fmt.Errorf("operation %q: want <name>:<argument>", s)
	}
	switch name {
	case Hash:
		if _, ok := parseHashArg(arg); !ok {
			return Op{}, hashArgError(s)
		}
	case TrimPrefix, TrimSuffix:
		if arg == "" || len(arg) > maxCNArg || !cnText(arg) {
			return Op{}, fmt.Errorf("operation %q: the argument must be 1 to %d characters from A-Z, a-z, 0-9, ., _, -, / and the colon", s, maxCNArg)
		}
	default:
		return Op{}, fmt.Errorf("operation %q: unknown operation %q; the operations are %s, %s and %s", s, name, TrimPrefix, TrimSuffix, Hash)
	}
	return Op{Name: name, Arg: arg}, nil
}

// String returns the template as written.
func (c *CN) String() string {
	var b strings.Builder
	b.WriteString(c.Lead)
	b.WriteString("{" + c.Placeholder)
	for _, op := range c.Ops {
		b.WriteString("|" + op.String())
	}
	b.WriteString("}")
	b.WriteString(c.Tail)
	return b.String()
}

// Value returns the placeholder's value for a SPIFFE ID, before its
// operations: the full ID or its path (starting with /).
func (c *CN) Value(spiffeID, path string) string {
	if c.Placeholder == CNSpiffeID {
		return spiffeID
	}
	return path
}

// Render fills the template for a SPIFFE ID, given as its full URI and its
// path. It refuses, and never shortens or rewrites, a value an operation does
// not apply to, an operation that leaves nothing, and a name outside 1 to
// MaxCNLength characters.
func (c *CN) Render(spiffeID, path string) (string, error) {
	raw := c.Value(spiffeID, path)
	v := raw
	for _, op := range c.Ops {
		left := v
		var ok bool
		if v, ok = op.apply(v); !ok {
			return "", fmt.Errorf("{%s} is %q, to which %s does not apply", c.Placeholder, left, op)
		}
	}
	if v == "" {
		return "", fmt.Errorf("{%s} is %q, which its operations leave empty", c.Placeholder, raw)
	}
	out := c.Lead + v + c.Tail
	if strings.HasPrefix(out, "/") {
		return "", fmt.Errorf("the common name %q starts with /, which PostgreSQL reads as a regular expression", out)
	}
	if len(out) > MaxCNLength {
		return "", fmt.Errorf("the common name %q is %d characters, more than the %d allowed", out, len(out), MaxCNLength)
	}
	return out, nil
}
