package nametemplate

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		template string
		ok       bool
	}{
		{"", true},
		{"a/{b}/c", true},
		{"{a/b|trim_prefix:x|trim_suffix:y}", true},
		{"{a:b|trim_prefix:x}", true},
		{"{a|trim_prefix:.}", true},
		{"{a|trim_prefix:x|}", false},
		{"{a||trim_prefix:x}", false},
		{"{a|trim_prefix:a:b}", false},
		{"{a|trim_prefix:a/b}", false},
		{"{a|lower:x}", false},
		{"{a|trim_prefix}", false},
		{"x{a}", false},
		{"a/", false},
		{"{}", false},
		{"a/{}/b", false},
		{"{|trim_prefix:a}", false},
	}
	for _, tt := range tests {
		tmpl, err := Parse(tt.template, Options{})
		if (err == nil) != tt.ok {
			t.Errorf("%q: err = %v", tt.template, err)
			continue
		}
		if err == nil && tmpl.String() != tt.template {
			t.Errorf("%q reads back as %q", tt.template, tmpl.String())
		}
	}
}

func TestParseOptions(t *testing.T) {
	refuse := errors.New("not this one")
	opts := Options{CheckPlaceholder: func(name string) error {
		if name == "bad" {
			return refuse
		}
		return nil
	}}
	if _, err := Parse("{bad}", opts); !errors.Is(err, refuse) {
		t.Errorf("CheckPlaceholder: err = %v", err)
	}
	if _, err := Parse("{good}", opts); err != nil {
		t.Errorf("CheckPlaceholder: err = %v", err)
	}
	_, err := Parse("{a|trim_prefix:x}", Options{NoOps: true})
	if !errors.Is(err, ErrNoOps) || !strings.Contains(err.Error(), "{a} takes no operations") {
		t.Errorf("NoOps: err = %v", err)
	}
}

func TestRender(t *testing.T) {
	tests := []struct {
		template string
		value    string
		want     string
		ok       bool
	}{
		{"{v}", "dev", "dev", true},
		{"{v|trim_prefix:customer-}", "customer-dev", "dev", true},
		{"{v|trim_prefix:customer-}", "dev", "", false},
		{"{v|trim_prefix:customer-}", "customer-", "", false},
		{"{v|trim_prefix:customer-}", "customer-a/b", "", false},
		{"{v|trim_prefix:customer-}", "customer-.", "", false},
		{"{v|trim_suffix:-prod}", "shop-prod", "shop", true},
		{"{v|trim_suffix:-prod}", "shop", "", false},
		{"{v|trim_prefix:a-|trim_suffix:-z}", "a-m-z", "m", true},
		{"{v|trim_prefix:a-|trim_suffix:-z}", "a-m", "", false},
		{"{v|trim_prefix:a-|trim_prefix:a-}", "a-a-m", "m", true},
		{"{v|trim_prefix:a-|trim_prefix:a-}", "a-m", "", false},
		{"t/{v|trim_prefix:customer-}/backend", "customer-dev", "t/dev/backend", true},
		{"{v|trim_suffix:-prod}", "..-prod", "", false},
		{"{v|trim_suffix:-prod}", ".-prod", "", false},
	}
	for _, tt := range tests {
		tmpl, err := Parse(tt.template, Options{})
		if err != nil {
			t.Fatalf("%q: %v", tt.template, err)
		}
		got, errs := tmpl.Render(func(string) (string, bool) { return tt.value, true })
		if (len(errs) == 0) != tt.ok {
			t.Errorf("%q with %q: errors = %v", tt.template, tt.value, errs)
			continue
		}
		if tt.ok && got != tt.want {
			t.Errorf("%q with %q = %q, want %q", tt.template, tt.value, got, tt.want)
		}
	}
}

func TestShortestIgnoresOperations(t *testing.T) {
	tmpl, err := Parse("a/{v|trim_prefix:long-prefix-}", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := tmpl.Shortest(); got != "a/x" {
		t.Errorf("Shortest = %q, want a/x", got)
	}
}

func TestRenderErrors(t *testing.T) {
	tests := []struct {
		template, value, want string
	}{
		{"{v}", "a/b", `{v} is "a/b", which is not a valid path segment`},
		{"{v|trim_prefix:x}", "z", `{v} is "z", to which trim_prefix:x does not apply`},
		{"{v|trim_prefix:x|trim_prefix:y}", "xz", `{v} is "xz", and trim_prefix:y does not apply to "z", what the operations before it left`},
		{"{v|trim_prefix:x}", "x.", `{v} is "x.", which its operations make ".", not a valid path segment`},
	}
	for _, tt := range tests {
		tmpl, err := Parse(tt.template, Options{})
		if err != nil {
			t.Fatal(err)
		}
		_, errs := tmpl.Render(func(string) (string, bool) { return tt.value, true })
		if len(errs) != 1 || errs[0].Error() != tt.want {
			t.Errorf("%q with %q: errors = %q, want %q", tt.template, tt.value, errs, tt.want)
		}
	}
}

func TestRenderErrorFields(t *testing.T) {
	tmpl, err := Parse("{v|trim_prefix:x|trim_prefix:y}", Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, errs := tmpl.Render(func(string) (string, bool) { return "xz", true })
	if len(errs) != 1 {
		t.Fatalf("errs = %v", errs)
	}
	if e := errs[0]; e.Refusal != OpRefused || e.Placeholder != "v" || e.Value != "xz" || e.OpIndex != 1 || e.Left != "z" || e.Op.String() != "trim_prefix:y" {
		t.Errorf("error = %+v", errs[0])
	}
	_, errs = tmpl.Render(func(string) (string, bool) { return "", false })
	if len(errs) != 1 || errs[0].Error() != "no value for {v}" {
		t.Errorf("missing: errs = %v", errs)
	}
}
