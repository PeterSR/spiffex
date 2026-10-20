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

// The vectors are the SHA-256 of the value, in lowercase unpadded base32.
func TestHashValue(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abc", "xj4bnp4pahh6uqkbidpf3lrceoyagyndsylxvhfucd7wd4qacwwq"},
		{"", "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq"},
		{"/tenants/kokkenogco/backend", "ufprsusxu3qhzkgyalgz55d5jd6dmdaikbqvoy5pfewg3byyfsiq"},
	}
	for _, tt := range tests {
		if got := HashValue(tt.in, MaxHashLength); got != tt.want {
			t.Errorf("HashValue(%q, %d) = %q, want %q", tt.in, MaxHashLength, got, tt.want)
		}
		if got := HashValue(tt.in, MinHashLength); got != tt.want[:MinHashLength] {
			t.Errorf("HashValue(%q, %d) = %q, want %q", tt.in, MinHashLength, got, tt.want[:MinHashLength])
		}
	}
}

func TestHashOperationInNames(t *testing.T) {
	for _, tt := range []struct {
		template, value, want string
		ok                    bool
	}{
		{"{v|hash:24}", "abc", "xj4bnp4pahh6uqkbidpf3lrc", true},
		{"{v|hash:52}", "abc", "xj4bnp4pahh6uqkbidpf3lrceoyagyndsylxvhfucd7wd4qacwwq", true},
		{"t/{v|hash:24}/x", "abc", "t/xj4bnp4pahh6uqkbidpf3lrc/x", true},
		// Any value can be hashed, whatever it holds.
		{"{v|hash:24}", "a/b c", HashValue("a/b c", 24), true},
		// Trims before and after.
		{"{v|trim_prefix:team-|hash:24}", "team-abc", "xj4bnp4pahh6uqkbidpf3lrc", true},
		{"{v|trim_prefix:team-|hash:24}", "abc", "", false},
		{"{v|hash:24|trim_prefix:xj4b}", "abc", "np4pahh6uqkbidpf3lrc", true},
		{"{v|hash:24|trim_prefix:zz}", "abc", "", false},
	} {
		tmpl, err := Parse(tt.template, Options{})
		if err != nil {
			t.Fatalf("%q: %v", tt.template, err)
		}
		got, errs := tmpl.Render(func(string) (string, bool) { return tt.value, true })
		if (len(errs) == 0) != tt.ok || tt.ok && got != tt.want {
			t.Errorf("%q with %q = %q, %v; want %q, ok %v", tt.template, tt.value, got, errs, tt.want, tt.ok)
		}
		if tt.ok && !ValidSegment(strings.Split(got, "/")[len(strings.Split(got, "/"))-1]) {
			t.Errorf("%q: %q is not a valid segment", tt.template, got)
		}
	}
}

func TestHashArgument(t *testing.T) {
	for _, arg := range []string{"15", "23", "53", "0", "-16", "+16", "016", "1e1", "16.0", " 16", "x", "", "99999999999999999999"} {
		if _, err := Parse("{v|hash:"+arg+"}", Options{}); err == nil {
			t.Errorf("hash:%q parsed", arg)
		}
		if _, err := ParseCN("{path|hash:" + arg + "}"); err == nil {
			t.Errorf("CN hash:%q parsed", arg)
		}
	}
	for _, arg := range []string{"24", "25", "51", "52"} {
		if _, err := Parse("{v|hash:"+arg+"}", Options{}); err != nil {
			t.Errorf("hash:%s: %v", arg, err)
		}
	}
	if _, err := Parse("{v|hash}", Options{}); err == nil {
		t.Error("hash without an argument parsed")
	}
	if _, err := Parse("{v|hash:24}", Options{NoOps: true}); !errors.Is(err, ErrNoOps) {
		t.Errorf("NoOps: err = %v", err)
	}
}

func TestParseCN(t *testing.T) {
	for _, tt := range []struct {
		in string
		ok bool
	}{
		{"{path}", true},
		{"{spiffe_id}", true},
		{"/{path}", false},
		{"/b{path}", false},
		{"//x{path}", false},
		{"b/{path}", true},
		{"{path|trim_prefix:/tenants/}", true},
		{"{path|trim_prefix:/tenants/|trim_suffix:/backend}", true},
		{"{spiffe_id|trim_prefix:spiffe://example.org}", true},
		{"{path|hash:24}", true},
		{"{path|trim_prefix:/tenants/|hash:24}", true},
		{"pg:{path|hash:24}", true},
		{"{path}:db", true},
		{"app-{path|trim_prefix:/a/}.v1", true},
		// No placeholder, two, or an unknown one.
		{"fixed", false},
		{"", false},
		{"{path}{path}", false},
		{"{path}/{path}", false},
		{"{kubernetes.io/namespace}", false},
		{"{}", false},
		{"{path", false},
		{"path}", false},
		{"}{path}", false},
		// A hash is last, and there is at most one.
		{"{path|hash:24|trim_prefix:x}", false},
		{"{path|hash:24|hash:24}", false},
		// Operations.
		{"{path|}", false},
		{"{path|upper:x}", false},
		{"{path|trim_prefix}", false},
		{"{path|trim_prefix:}", false},
		{"{path|trim_prefix:" + strings.Repeat("a", 65) + "}", false},
		// Characters outside the conservative set.
		{"a b{path}", false},
		{"{path}=x", false},
		{"{path}\"", false},
		{"{path},", false},
		{"é{path}", false},
		{"{path|trim_prefix:a b}", false},
		// The text alone leaves no room.
		{strings.Repeat("a", 64) + "{path}", false},
		{strings.Repeat("a", 30) + "{path}" + strings.Repeat("b", 34), false},
		{strings.Repeat("a", 30) + "{path}" + strings.Repeat("b", 33), true},
	} {
		cn, err := ParseCN(tt.in)
		if (err == nil) != tt.ok {
			t.Errorf("%q: err = %v", tt.in, err)
			continue
		}
		if err == nil && cn.String() != tt.in {
			t.Errorf("%q reads back as %q", tt.in, cn.String())
		}
	}
}

func TestRenderCN(t *testing.T) {
	const id = "spiffe://example.org/tenants/kokkenogco/backend"
	const path = "/tenants/kokkenogco/backend"
	for _, tt := range []struct {
		template, want string
		ok             bool
	}{
		{"{spiffe_id}", id, true},
		{"{path|trim_prefix:/}", "tenants/kokkenogco/backend", true},
		{"pg:{path}", "pg:" + path, true},
		// A name never starts with /, which PostgreSQL reads as a regex.
		{"{path}", "", false},
		{"{path|trim_suffix:/backend}", "", false},
		{"{path|trim_prefix:/tenants}", "", false},
		{"{path|trim_prefix:/tenants/}", "kokkenogco/backend", true},
		{"{path|trim_prefix:/tenants/|trim_suffix:/backend}", "kokkenogco", true},
		{"db:{path|trim_prefix:/tenants/}", "db:kokkenogco/backend", true},
		{"{path|trim_prefix:/tenants/}-pg", "kokkenogco/backend-pg", true},
		{"{spiffe_id|trim_prefix:spiffe://example.org}", "", false},
		{"{spiffe_id|trim_prefix:spiffe://example.org/}", "tenants/kokkenogco/backend", true},
		{"{path|hash:24}", HashValue(path, 24), true},
		{"x-{path|hash:30}", "x-" + HashValue(path, 30), true},
		{"{path|trim_prefix:/tenants/|hash:24}", HashValue("kokkenogco/backend", 24), true},
		// A trim that does not apply refuses the value.
		{"{path|trim_prefix:/other/}", "", false},
		{"{path|trim_suffix:/frontend}", "", false},
		// Nothing left.
		{"{path|trim_prefix:/tenants/kokkenogco/backend}", "", false},
		// Too long: the whole id is 47 characters, so text pushes it over.
		{strings.Repeat("a", 18) + "{spiffe_id}", "", false},
		{strings.Repeat("a", 17) + "{spiffe_id}", strings.Repeat("a", 17) + id, true},
	} {
		cn, err := ParseCN(tt.template)
		if err != nil {
			t.Fatalf("%q: %v", tt.template, err)
		}
		got, err := cn.Render(id, path)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("%q = %q, %v; want %q, ok %v", tt.template, got, err, tt.want, tt.ok)
		}
	}
}
