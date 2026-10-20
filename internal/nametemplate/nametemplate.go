// Package nametemplate parses and fills name templates: /-separated paths
// whose segments are literals or placeholders filled from looked-up values.
//
// A placeholder fills one whole segment with a value looked up by name, and
// may first pass it through operations:
//
//	ns/{kubernetes.io/namespace|trim_prefix:team-}/backend
//
// The trim operations are one-to-one: an operation that does not apply
// refuses the value instead of passing it through. Together with the rule
// that a filled segment is never escaped, this means two different values
// can never give the same name, unless a hash operation is used, which is
// one-to-one up to the collisions of a truncated SHA-256 (see Hash).
//
// The caller decides what a placeholder may name (Options.CheckPlaceholder)
// and supplies the values (the lookup passed to Render).
package nametemplate

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNoOps is wrapped in the error Parse returns for a placeholder with
// operations when Options.NoOps is set.
var ErrNoOps = errors.New("takes no operations")

// Operation names.
const (
	TrimPrefix = "trim_prefix"
	TrimSuffix = "trim_suffix"
	Hash       = "hash"
)

// The bounds of the argument of the hash operation: the number of characters
// kept. 24 base32 characters are 120 bits, and 52 is the whole digest.
const (
	MinHashLength = 24
	MaxHashLength = 52
)

var hashEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// HashValue returns the first n characters of the lowercase, unpadded base32
// (RFC 4648 alphabet) encoding of the SHA-256 digest of v. Its characters are
// a-z and 2-7, so it is a valid path segment. Two different values give the
// same result only when their digests agree on the first 5n bits, which for
// n of at least 16 means 120 bits.
func HashValue(v string, n int) string {
	sum := sha256.Sum256([]byte(v))
	return strings.ToLower(hashEncoding.EncodeToString(sum[:]))[:n]
}

// parseHashArg reads the argument of hash: a canonical decimal number from
// MinHashLength to MaxHashLength.
func parseHashArg(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s || n < MinHashLength || n > MaxHashLength {
		return 0, false
	}
	return n, true
}

// Template is a parsed name template. An empty template names nothing. Make
// one with Parse: a Template built by hand is not validated.
type Template []Part

// Part is one segment of a template: either literal text, or a placeholder
// whose value passes through its operations in order.
type Part struct {
	Literal     string
	Placeholder string
	Ops         []Op
}

// Op is one operation of a placeholder, written <name>:<argument>.
type Op struct {
	Name string
	Arg  string
}

// Options says what a template may contain.
type Options struct {
	// CheckPlaceholder, when set, refuses a placeholder name. Its error is
	// wrapped in the one Parse returns.
	CheckPlaceholder func(name string) error
	// NoOps refuses placeholders with operations.
	NoOps bool
}

// Parse parses a template. A placeholder ends at the first } and its name at
// the first |, so a name containing either cannot be a placeholder. Names may
// contain /, so placeholders are read before the text is split into segments.
func Parse(s string, opts Options) (Template, error) {
	var t Template
	for rest := s; rest != ""; {
		var part string
		if strings.HasPrefix(rest, "{") {
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return nil, fmt.Errorf("template %q: unclosed {", s)
			}
			part, rest = rest[:end+1], rest[end+1:]
			inner := part[1 : len(part)-1]
			if strings.Contains(inner, "{") {
				return nil, fmt.Errorf("template %q: %q is not a single placeholder", s, part)
			}
			name, opsText, hasOps := strings.Cut(inner, "|")
			if name == "" {
				return nil, fmt.Errorf("template %q: %q has no placeholder name", s, part)
			}
			if opts.CheckPlaceholder != nil {
				if err := opts.CheckPlaceholder(name); err != nil {
					return nil, fmt.Errorf("template %q: %w", s, err)
				}
			}
			if hasOps && opts.NoOps {
				return nil, fmt.Errorf("template %q: {%s} %w", s, name, ErrNoOps)
			}
			p := Part{Placeholder: name}
			if hasOps {
				for _, opText := range strings.Split(opsText, "|") {
					op, err := parseOp(opText)
					if err != nil {
						return nil, fmt.Errorf("template %q: %w", s, err)
					}
					p.Ops = append(p.Ops, op)
				}
			}
			t = append(t, p)
		} else {
			end := strings.IndexByte(rest, '/')
			if end < 0 {
				end = len(rest)
			}
			part, rest = rest[:end], rest[end:]
			if strings.ContainsAny(part, "{}") {
				return nil, fmt.Errorf("template %q: a placeholder must fill a whole segment", s)
			}
			if err := CheckSegment(part); err != nil {
				return nil, fmt.Errorf("template %q: %w", s, err)
			}
			t = append(t, Part{Literal: part})
		}
		if rest == "" {
			break
		}
		if rest[0] != '/' {
			return nil, fmt.Errorf("template %q: a placeholder must fill a whole segment", s)
		}
		rest = rest[1:]
		if rest == "" {
			return nil, fmt.Errorf("template %q: ends with /", s)
		}
	}
	return t, nil
}

// parseOp parses one operation. The argument takes only characters a segment
// may hold, so it never contains the |, } or / that would end it.
func parseOp(s string) (Op, error) {
	name, arg, ok := strings.Cut(s, ":")
	if !ok {
		return Op{}, fmt.Errorf("operation %q: want <name>:<argument>", s)
	}
	if name == Hash {
		if _, ok := parseHashArg(arg); !ok {
			return Op{}, hashArgError(s)
		}
		return Op{Name: name, Arg: arg}, nil
	}
	if name != TrimPrefix && name != TrimSuffix {
		return Op{}, fmt.Errorf("operation %q: unknown operation %q; the operations are %s, %s and %s", s, name, TrimPrefix, TrimSuffix, Hash)
	}
	if !segmentText(arg) {
		return Op{}, fmt.Errorf("operation %q: the argument must be 1 to 255 characters from A-Z, a-z, 0-9, ., _ and -", s)
	}
	return Op{Name: name, Arg: arg}, nil
}

func hashArgError(s string) error {
	return fmt.Errorf("operation %q: the argument of %s must be a whole number from %d to %d", s, Hash, MinHashLength, MaxHashLength)
}

// segmentText reports whether s is 1 to 255 characters a segment may hold.
// Unlike a segment, it may be . or .. alone.
func segmentText(s string) bool {
	return s == "." || s == ".." || ValidSegment(s)
}

// apply runs the operation on v. A trim whose text is not there refuses the
// value rather than passing it through, or x and <prefix>x would both
// become x. A hash always applies.
func (op Op) apply(v string) (string, bool) {
	switch op.Name {
	case TrimPrefix:
		return strings.CutPrefix(v, op.Arg)
	case TrimSuffix:
		return strings.CutSuffix(v, op.Arg)
	case Hash:
		n, ok := parseHashArg(op.Arg)
		if !ok {
			return "", false
		}
		return HashValue(v, n), true
	}
	return "", false
}

// HashLength returns the number of characters a hash operation keeps.
func (op Op) HashLength() (int, bool) {
	if op.Name != Hash {
		return 0, false
	}
	return parseHashArg(op.Arg)
}

func (op Op) String() string { return op.Name + ":" + op.Arg }

// String returns the template as written.
func (t Template) String() string {
	parts := make([]string, len(t))
	for i, p := range t {
		if p.Placeholder == "" {
			parts[i] = p.Literal
			continue
		}
		parts[i] = "{" + p.Placeholder
		for _, op := range p.Ops {
			parts[i] += "|" + op.String()
		}
		parts[i] += "}"
	}
	return strings.Join(parts, "/")
}

// Refusal is why Render refused a placeholder's value.
type Refusal int

const (
	// Missing: the lookup found no value.
	Missing Refusal = iota
	// OpRefused: an operation did not apply.
	OpRefused
	// InvalidSegment: the value, after any operations, is not a valid
	// segment.
	InvalidSegment
)

func (r Refusal) String() string {
	switch r {
	case Missing:
		return "missing"
	case OpRefused:
		return "operation refused"
	case InvalidSegment:
		return "invalid segment"
	}
	return fmt.Sprintf("Refusal(%d)", int(r))
}

// RenderError says why a placeholder's value was refused.
type RenderError struct {
	Refusal     Refusal
	Placeholder string
	// Value is the looked-up value, unless Missing.
	Value string
	// For OpRefused: the operation, its index among the placeholder's
	// operations, and the value it was given.
	Op      Op
	OpIndex int
	Left    string
	// For InvalidSegment: whether operations ran, and the value they left.
	Operated bool
	Result   string
}

func (e *RenderError) Error() string {
	switch {
	case e.Refusal == Missing:
		return fmt.Sprintf("no value for {%s}", e.Placeholder)
	case e.Refusal == OpRefused && e.OpIndex == 0:
		return fmt.Sprintf("{%s} is %q, to which %s does not apply", e.Placeholder, e.Value, e.Op)
	case e.Refusal == OpRefused:
		return fmt.Sprintf("{%s} is %q, and %s does not apply to %q, what the operations before it left", e.Placeholder, e.Value, e.Op, e.Left)
	case e.Operated:
		return fmt.Sprintf("{%s} is %q, which its operations make %q, not a valid path segment", e.Placeholder, e.Value, e.Result)
	}
	return fmt.Sprintf("{%s} is %q, which is not a valid path segment", e.Placeholder, e.Value)
}

// Render fills the template, looking each placeholder's value up by name. A
// value is refused, never escaped or rewritten, when it is absent, an
// operation does not apply to it, or it does not end up a valid segment. The
// name is only meaningful when no errors are returned.
func (t Template) Render(lookup func(name string) (string, bool)) (string, []*RenderError) {
	parts := make([]string, len(t))
	var errs []*RenderError
	for i, p := range t {
		if p.Placeholder == "" {
			parts[i] = p.Literal
			continue
		}
		raw, ok := lookup(p.Placeholder)
		if !ok {
			errs = append(errs, &RenderError{Refusal: Missing, Placeholder: p.Placeholder})
			continue
		}
		v := raw
		for j, op := range p.Ops {
			left := v
			if v, ok = op.apply(v); !ok {
				errs = append(errs, &RenderError{Refusal: OpRefused, Placeholder: p.Placeholder, Value: raw, Op: op, OpIndex: j, Left: left})
				break
			}
		}
		if ok && !ValidSegment(v) {
			errs = append(errs, &RenderError{Refusal: InvalidSegment, Placeholder: p.Placeholder, Value: raw, Operated: len(p.Ops) > 0, Result: v})
		}
		parts[i] = v
	}
	return strings.Join(parts, "/"), errs
}

// Shortest fills the template with the shortest possible segments, for
// checking the length of the names it can produce.
func (t Template) Shortest() string {
	parts := make([]string, len(t))
	for i, p := range t {
		if p.Placeholder == "" {
			parts[i] = p.Literal
		} else {
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

// ValidSegment reports whether s may be one segment of a name, by the rules
// of a SPIFFE ID path segment. It may be called on hot paths, so it loops
// over bytes rather than running a regular expression.
func ValidSegment(s string) bool {
	if len(s) == 0 || len(s) > 255 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// CheckSegment is ValidSegment with an error that says what a segment is.
func CheckSegment(s string) error {
	if !ValidSegment(s) {
		return fmt.Errorf("%q is not a path segment: want 1 to 255 characters from A-Z, a-z, 0-9, ., _ and -, other than . and .. alone", s)
	}
	return nil
}
