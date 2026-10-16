package state

import (
	"slices"
	"strings"
	"testing"
)

func TestSplitClaimPath(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"sub", []string{"sub"}},
		{"kubernetes.io/namespace", []string{"kubernetes.io", "namespace"}},
		{"oidc.circleci.com~1project-id", []string{"oidc.circleci.com/project-id"}},
		{"a~0b/c~01", []string{"a~b", "c~1"}},
		{"~1~0", []string{"/~"}},
		{"", nil},
		{"a//b", nil},
		{"/a", nil},
		{"a/", nil},
		{"a~", nil},
		{"a~2", nil},
		{"~x", nil},
	}
	for _, tt := range tests {
		got, err := splitClaimPath(tt.path)
		if tt.want == nil {
			if err == nil {
				t.Errorf("%q was accepted as %q", tt.path, got)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("%q = %q, %v; want %q", tt.path, got, err, tt.want)
		}
	}
}

func TestClaimValue(t *testing.T) {
	claims, err := DecodeClaims([]byte(`{
		"sub": "x",
		"empty": "",
		"n": 42,
		"f": 4.2,
		"big": 12345678901234567890123,
		"b": true,
		"oidc.circleci.com/project-id": "p-1",
		"a~b": "tilde",
		"kubernetes.io": {"namespace": "ns", "empty": ""}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"sub":                           "x",
		"n":                             "42",
		"big":                           "12345678901234567890123",
		"oidc.circleci.com~1project-id": "p-1",
		"a~0b":                          "tilde",
		"kubernetes.io/namespace":       "ns",
	} {
		if got, ok := ClaimValue(claims, path); !ok || got != want {
			t.Errorf("%s = %q, %v; want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{"empty", "kubernetes.io/empty", "f", "b", "kubernetes.io", "missing", "sub/x", "oidc.circleci.com/project-id", "a~b"} {
		if v, ok := ClaimValue(claims, path); ok {
			t.Errorf("%s = %q, want absent", path, v)
		}
	}
}

func TestDecodeClaimsIsStrict(t *testing.T) {
	for name, payload := range map[string]string{
		"duplicate at the top":  `{"sub": "a", "sub": "b"}`,
		"duplicate nested":      `{"x": {"y": 1, "y": 2}}`,
		"duplicate in an array": `{"x": [{"y": 1, "y": 2}]}`,
		"trailing object":       `{"sub": "a"} {"sub": "b"}`,
		"trailing garbage":      `{"sub": "a"} x`,
		"not an object":         `["sub"]`,
		"null":                  `null`,
		"empty":                 ``,
		"truncated":             `{"sub": "a"`,
		"too deep":              strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100),
	} {
		if _, err := DecodeClaims([]byte(payload)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeClaims([]byte(" {\"sub\": \"a\", \"x\": [1, {\"y\": null}]}\n")); err != nil {
		t.Error(err)
	}
}

// The CircleCI owner claim is a top-level claim whose name contains /, so
// the well-known table escapes it, and an origin can pin it.
func TestCircleCIOwnerClaim(t *testing.T) {
	r := check(t, `
origins:
  circle:
    provider: oidc
    with: { issuer: "https://oidc.circleci.com/org/0d3e", owner_claims: [sub] }
    match: { oidc.circleci.com~1project-id: "p-1" }
`)
	wantValid(t, r)
	claims, _ := DecodeClaims([]byte(`{"sub": "org/0d3e/project/p-1/user/u", "oidc.circleci.com/project-id": "p-1"}`))
	e := r.Origins["circle"]
	e.Template = Template{{Literal: "x"}}
	if _, err := e.Admit(td, claims); err != nil {
		t.Errorf("admit: %v", err.(*RefusedError).LogDetail())
	}
	unpinned := check(t, `
origins:
  circle:
    provider: oidc
    with: { issuer: "https://oidc.circleci.com/org/0d3e", owner_claims: [sub] }
    match: { sub: "x" }
`)
	wantProblem(t, unpinned, "origins.circle.match", "one of oidc.circleci.com~1project-id")
}
