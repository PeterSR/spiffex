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
// member's name).
type TemplatePart struct {
	Literal     string
	Placeholder string
}

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
			if kind == KindKeys && inner != memberPlaceholder {
				return nil, fmt.Errorf("template %q: a keys origin's only placeholder is {member}", s)
			}
			if err := checkClaimPath(inner); err != nil {
				return nil, fmt.Errorf("template %q: %w", s, err)
			}
			t = append(t, TemplatePart{Placeholder: inner})
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

// String returns the template as written.
func (t Template) String() string {
	parts := make([]string, len(t))
	for i, p := range t {
		if p.Placeholder != "" {
			parts[i] = "{" + p.Placeholder + "}"
		} else {
			parts[i] = p.Literal
		}
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
		v, ok := lookup(p.Placeholder)
		switch {
		case !ok:
			reasons = append(reasons, fmt.Sprintf("the name needs claim %s, which is absent or neither a string nor an integer", p.Placeholder))
		case !validSegment(v):
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, which is not a valid path segment", p.Placeholder, v))
		}
		parts[i] = v
	}
	return strings.Join(parts, "/"), reasons
}

// sample renders the template with the shortest possible values, for
// checking the length of the IDs it can produce.
func (t Template) sample() string {
	name, _ := t.render(func(string) (string, bool) { return "x", true })
	return name
}
