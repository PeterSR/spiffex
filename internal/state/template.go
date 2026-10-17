package state

import (
	"fmt"
	"strings"
)

// memberPlaceholder is the only placeholder of a keys origin's template.
const memberPlaceholder = "member"

// Template is a parsed name template (SPEC section 4.1). An empty template
// names nothing beyond the prefix.
type Template []TemplatePart

// TemplatePart is one segment of a template: either literal text, or a
// placeholder filled with a claim's value (or, in a keys origin, the
// member's name), passed through its operations in order.
type TemplatePart struct {
	Literal     string
	Placeholder string
	Ops         []TemplateOp
}

// TemplateOp is one operation of a placeholder. Every operation is
// one-to-one, so two different values never become the same segment.
type TemplateOp struct {
	Name string
	Arg  string
}

const (
	opTrimPrefix = "trim_prefix"
	opTrimSuffix = "trim_suffix"
)

// ParseTemplate parses a name template for an origin of the given kind.
// Placeholders are read first, since a claim path inside one may itself
// contain /.
func ParseTemplate(s string, kind Kind) (Template, error) {
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
			path, opsText, hasOps := strings.Cut(inner, "|")
			if kind == KindKeys && path != memberPlaceholder {
				return nil, fmt.Errorf("template %q: a keys origin's only placeholder is {member}", s)
			}
			if kind == KindKeys && hasOps {
				return nil, fmt.Errorf("template %q: a keys origin's {member} takes no operations", s)
			}
			if err := checkClaimPath(path); err != nil {
				return nil, fmt.Errorf("template %q: %w", s, err)
			}
			tp := TemplatePart{Placeholder: path}
			if hasOps {
				for _, opText := range strings.Split(opsText, "|") {
					op, err := parseTemplateOp(opText)
					if err != nil {
						return nil, fmt.Errorf("template %q: %w", s, err)
					}
					tp.Ops = append(tp.Ops, op)
				}
			}
			t = append(t, tp)
		} else {
			end := strings.IndexByte(rest, '/')
			if end < 0 {
				end = len(rest)
			}
			part, rest = rest[:end], rest[end:]
			if strings.ContainsAny(part, "{}") {
				return nil, fmt.Errorf("template %q: a placeholder must fill a whole segment", s)
			}
			if err := checkSegment(part); err != nil {
				return nil, fmt.Errorf("template %q: %w", s, err)
			}
			t = append(t, TemplatePart{Literal: part})
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

// parseTemplateOp parses one operation, written <name>:<argument>. The
// argument takes only characters a segment may hold, so it never contains
// the |, } or / that would end it.
func parseTemplateOp(s string) (TemplateOp, error) {
	name, arg, ok := strings.Cut(s, ":")
	if !ok {
		return TemplateOp{}, fmt.Errorf("operation %q: want <name>:<argument>", s)
	}
	if name != opTrimPrefix && name != opTrimSuffix {
		return TemplateOp{}, fmt.Errorf("operation %q: unknown operation %q; the operations are %s and %s", s, name, opTrimPrefix, opTrimSuffix)
	}
	if !segmentText(arg) {
		return TemplateOp{}, fmt.Errorf("operation %q: the argument must be 1 to 255 characters from A-Z, a-z, 0-9, ., _ and -", s)
	}
	return TemplateOp{Name: name, Arg: arg}, nil
}

// segmentText reports whether s is 1 to 255 characters a segment may hold.
// Unlike a segment, it may be . or .. alone.
func segmentText(s string) bool {
	return s == "." || s == ".." || validSegment(s)
}

// apply runs the operation on v. A trim whose text is not there refuses the
// value rather than passing it through, or the values x and <prefix>x would
// both become x.
func (op TemplateOp) apply(v string) (string, bool) {
	switch op.Name {
	case opTrimPrefix:
		return strings.CutPrefix(v, op.Arg)
	case opTrimSuffix:
		return strings.CutSuffix(v, op.Arg)
	}
	return "", false
}

func (op TemplateOp) String() string { return op.Name + ":" + op.Arg }

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

// render fills the template. A value that is not a valid segment is refused,
// never escaped or rewritten, so two different tokens cannot be given the
// same name by way of a crafted value.
func (t Template) render(lookup func(placeholder string) (string, bool)) (string, []string) {
	parts := make([]string, len(t))
	var reasons []string
	for i, p := range t {
		if p.Placeholder == "" {
			parts[i] = p.Literal
			continue
		}
		raw, ok := lookup(p.Placeholder)
		if !ok {
			reasons = append(reasons, fmt.Sprintf("the name needs claim %s, which is absent or neither a string nor an integer", p.Placeholder))
			continue
		}
		v := raw
		for j, op := range p.Ops {
			before := v
			if v, ok = op.apply(v); !ok {
				if j == 0 {
					reasons = append(reasons, fmt.Sprintf("claim %s is %q, to which %s does not apply", p.Placeholder, raw, op))
				} else {
					reasons = append(reasons, fmt.Sprintf("claim %s is %q, and %s does not apply to %q, what the operations before it left", p.Placeholder, raw, op, before))
				}
				break
			}
		}
		switch {
		case !ok:
		case !validSegment(v) && len(p.Ops) > 0:
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, which its operations make %q, not a valid path segment", p.Placeholder, raw, v))
		case !validSegment(v):
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, which is not a valid path segment", p.Placeholder, v))
		}
		parts[i] = v
	}
	return strings.Join(parts, "/"), reasons
}

// sample fills the template with the shortest possible segments, for
// checking the length of the IDs it can produce.
func (t Template) sample() string {
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
