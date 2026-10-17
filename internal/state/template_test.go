package state

import (
	"strings"
	"testing"
)

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		template string
		kind     Kind
		ok       bool
	}{
		{"", KindJWT, true},
		{"{sub}", KindJWT, true},
		{"ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}", KindJWT, true},
		{"{a}/{b}", KindExec, true},
		{"{member}", KindKeys, true},
		{"fleet/{member}", KindKeys, true},
		{"{sub}", KindKeys, false},
		{"{}", KindJWT, false},
		{"{a//b}", KindJWT, false},
		{"{a", KindJWT, false},
		{"a}", KindJWT, false},
		{"{a}{b}", KindJWT, false},
		{"{{a}}", KindJWT, false},
		{"x{a}", KindJWT, false},
		{"/a", KindJWT, false},
		{"a/", KindJWT, false},
		{"a/./b", KindJWT, false},
		{"{kubernetes.io/namespace|trim_prefix:customer-}/backend", KindJWT, true},
		{"{sub|trim_prefix:a|trim_suffix:.b}", KindJWT, true},
		{"{sub|trim_prefix:.}", KindJWT, true},
		{"{sub|}", KindJWT, false},
		{"{sub|trim_prefix}", KindJWT, false},
		{"{sub|trim_prefix:}", KindJWT, false},
		{"{sub|trim_prefix:a/b}", KindJWT, false},
		{"{sub|trim_prefix:a b}", KindJWT, false},
		{"{sub|lower:x}", KindJWT, false},
		{"{|trim_prefix:a}", KindJWT, false},
		{"{member|trim_prefix:a}", KindKeys, false},
		{"{a:b|trim_prefix:x}", KindJWT, true},
		{"{oidc.circleci.com~1project-id|trim_suffix:-1}", KindJWT, true},
		{"{a|trim_prefix:x|}", KindJWT, false},
		{"{a||trim_prefix:x}", KindJWT, false},
		{"{a|trim_prefix:a:b}", KindJWT, false},
	}
	for _, tt := range tests {
		tmpl, err := ParseTemplate(tt.template, tt.kind)
		if (err == nil) != tt.ok {
			t.Errorf("%s template %q: err = %v", tt.kind, tt.template, err)
			continue
		}
		if err == nil && tmpl.String() != tt.template {
			t.Errorf("%q reads back as %q", tt.template, tmpl.String())
		}
	}
}

// One origin for every customer namespace, named without the namespace's
// common prefix.
func TestTemplateTrimAdmit(t *testing.T) {
	r := check(t, `
origins:
  customers:
    provider: kubernetes
    with: { namespaces: ["customer-*"] }
    match: { kubernetes.io/serviceaccount/name: customer }
    prefix: /customers
    name: "{kubernetes.io/namespace|trim_prefix:customer-}/backend"
`)
	wantValid(t, r)
	e := r.Origins["customers"]
	tokenFor := func(ns string) map[string]any {
		claims, err := DecodeClaims([]byte(`{"sub": "x", "kubernetes.io": {"namespace": "` + ns + `", "serviceaccount": {"name": "customer"}, "pod": {"name": "p"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		return claims
	}
	id, err := e.Admit(td, tokenFor("customer-dev"))
	if err != nil {
		t.Fatalf("admit: %v", err.(*RefusedError).LogDetail())
	}
	if got := id.String(); got != "spiffe://example.org/customers/dev/backend" {
		t.Errorf("id = %s", got)
	}
	if _, err := e.Admit(td, tokenFor("customer-")); err == nil {
		t.Error("admitted a namespace that trims to nothing")
	}

	bad := check(t, `
origins:
  customers:
    provider: kubernetes
    name: "{kubernetes.io/namespace|lower:x}"
`)
	wantProblem(t, bad, "origins.customers.name", "unknown operation")
}

// An integer claim, as written in the token, can be trimmed like a string.
func TestTemplateTrimIntegerClaim(t *testing.T) {
	tmpl, err := ParseTemplate("{id|trim_prefix:6}", KindJWT)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := DecodeClaims([]byte(`{"id": 600100200}`))
	if err != nil {
		t.Fatal(err)
	}
	got, reasons := renderName(tmpl, func(path string) (string, bool) { return ClaimValue(claims, path) })
	if len(reasons) > 0 || got != "00100200" {
		t.Errorf("got %q, %v", got, reasons)
	}
}

func TestKeysMemberTakesNoOperations(t *testing.T) {
	for _, tmpl := range []string{"{member|trim_prefix:a}", "{member|lower:x}", "{member|}", "{member|trim_prefix}"} {
		_, err := ParseTemplate(tmpl, KindKeys)
		if err == nil || !strings.Contains(err.Error(), "a keys origin's {member} takes no operations") {
			t.Errorf("%q: err = %v", tmpl, err)
		}
	}
}

func TestRenderNameReasons(t *testing.T) {
	tests := []struct {
		template, want string
		value          string
		ok             bool
	}{
		{"{v}", `the name needs claim v, which is absent or neither a string nor an integer`, "", false},
		{"{v}", `claim v is "a/b", which is not a valid path segment`, "a/b", true},
		{"{v|trim_prefix:x}", `claim v is "z", to which trim_prefix:x does not apply`, "z", true},
		{"{v|trim_prefix:x|trim_prefix:y}", `claim v is "xz", and trim_prefix:y does not apply to "z", what the operations before it left`, "xz", true},
		{"{v|trim_prefix:x}", `claim v is "x.", which its operations make ".", not a valid path segment`, "x.", true},
	}
	for _, tt := range tests {
		tmpl, err := ParseTemplate(tt.template, KindJWT)
		if err != nil {
			t.Fatal(err)
		}
		_, reasons := renderName(tmpl, func(string) (string, bool) { return tt.value, tt.ok })
		if len(reasons) != 1 || reasons[0] != tt.want {
			t.Errorf("%q with %q: reasons = %q, want %q", tt.template, tt.value, reasons, tt.want)
		}
	}
}
