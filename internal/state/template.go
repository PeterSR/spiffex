package state

import (
	"errors"
	"fmt"

	"github.com/PeterSR/spiffex/internal/nametemplate"
)

// memberPlaceholder is the only placeholder of a keys origin's template.
const memberPlaceholder = "member"

// Template is a parsed name template (SPEC section 4.1). An empty template
// names nothing beyond the prefix.
type Template = nametemplate.Template

// ParseTemplate parses a name template for an origin of the given kind: its
// placeholders name claims, or in a keys origin only {member}.
func ParseTemplate(s string, kind Kind) (Template, error) {
	if kind != KindKeys {
		return nametemplate.Parse(s, nametemplate.Options{CheckPlaceholder: checkClaimPath})
	}
	t, err := nametemplate.Parse(s, nametemplate.Options{
		CheckPlaceholder: func(name string) error {
			if name != memberPlaceholder {
				return errors.New("a keys origin's only placeholder is {member}")
			}
			return nil
		},
		NoOps: true,
	})
	if errors.Is(err, nametemplate.ErrNoOps) {
		return nil, fmt.Errorf("template %q: a keys origin's {member} takes no operations", s)
	}
	return t, err
}

// renderName fills a template from claims, returning why it could not as
// reasons in terms of claims.
func renderName(t Template, lookup func(name string) (string, bool)) (string, []string) {
	name, errs := t.Render(lookup)
	var reasons []string
	for _, e := range errs {
		switch {
		case e.Refusal == nametemplate.Missing:
			reasons = append(reasons, fmt.Sprintf("the name needs claim %s, which is absent or neither a string nor an integer", e.Placeholder))
		case e.Refusal == nametemplate.OpRefused && e.OpIndex == 0:
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, to which %s does not apply", e.Placeholder, e.Value, e.Op))
		case e.Refusal == nametemplate.OpRefused:
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, and %s does not apply to %q, what the operations before it left", e.Placeholder, e.Value, e.Op, e.Left))
		case e.Operated:
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, which its operations make %q, not a valid path segment", e.Placeholder, e.Value, e.Result))
		default:
			reasons = append(reasons, fmt.Sprintf("claim %s is %q, which is not a valid path segment", e.Placeholder, e.Value))
		}
	}
	return name, reasons
}
