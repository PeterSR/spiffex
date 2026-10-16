package state

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

func pat(t *testing.T, path string) IDPattern {
	t.Helper()
	p, err := ParseIDPattern("spiffe://example.org"+path, td)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseIDPattern(t *testing.T) {
	for _, ok := range []string{"/a", "/a/*", "/*", "/**", "/a/**", "/*/b/**", "/a.b/c_d-e"} {
		if _, err := ParseIDPattern("spiffe://example.org"+ok, td); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"spiffe://example.org",
		"spiffe://example.org/",
		"spiffe://example.org/a/",
		"spiffe://example.org//a",
		"spiffe://example.org/**/a",
		"spiffe://example.org/a*",
		"spiffe://example.org/..",
		"spiffe://example.org/a?b",
		"spiffe://other.org/a",
		"https://example.org/a",
	} {
		if _, err := ParseIDPattern(bad, td); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

func TestIDPatternMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/vms/billing", "/vms/billing", true},
		{"/vms/billing", "/vms/billing/x", false},
		{"/vms/*", "/vms/billing", true},
		{"/vms/*", "/vms", false},
		{"/vms/*", "/vms/a/b", false},
		{"/vms/**", "/vms/a/b", true},
		{"/vms/**", "/vms/a", true},
		{"/vms/**", "/vms", false},
		{"/**", "/x", true},
		{"/*/admin", "/ci/admin", true},
		{"/*/admin", "/ci/other", false},
	}
	for _, tt := range tests {
		p := pat(t, tt.pattern)
		if got := p.MatchPath(tt.path); got != tt.want {
			t.Errorf("%s matches %s = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
		id := spiffeid.RequireFromPath(td, tt.path)
		if got := p.Match(id); got != tt.want {
			t.Errorf("%s matches ID %s = %v, want %v", tt.pattern, id, got, tt.want)
		}
	}
	other := spiffeid.RequireFromString("spiffe://other.org/vms/billing")
	if pat(t, "/vms/billing").Match(other) {
		t.Error("a pattern matched an ID in another trust domain")
	}
}

func TestLiteralPrefix(t *testing.T) {
	for pattern, want := range map[string]string{"/a/b": "/a/b", "/a/*/c": "/a", "/**": "/", "/a/b/**": "/a/b"} {
		if got := pat(t, pattern).LiteralPrefix(); got != want {
			t.Errorf("%s: literal prefix %s, want %s", pattern, got, want)
		}
	}
}

func TestReaches(t *testing.T) {
	tests := []struct {
		scope, who string
		want       bool
	}{
		{"/vms", "/vms/*", true},
		{"/vms", "/*/admin", true},
		{"/vms", "/**", true},
		{"/vms", "/vms", true},
		{"/vms", "/other/**", false},
		{"/", "/a", true},
		{"/", "/**", true},
		{"/vms/a", "/vms", false},
		{"/vms/a", "/vms/*", true},
		{"/vms/a/b", "/vms/*", false},
		{"/vms/a/b", "/vms/**", true},
		{"/vms/a/b", "/*/a/**", true},
		{"/vmsx", "/vms/*", false},
	}
	for _, tt := range tests {
		if got := Reaches(tt.scope, pat(t, tt.who)); got != tt.want {
			t.Errorf("%s reaches %s = %v, want %v", tt.scope, tt.who, got, tt.want)
		}
	}
}

func TestCovers(t *testing.T) {
	tests := []struct {
		p, q string
		want bool
	}{
		{"/**", "/a/*", true},
		{"/a/**", "/a", false},
		{"/*", "/**", false},
		{"/a/**", "/a/**", true},
		{"/*/*/**", "/a/**", false},
		{"/*/**", "/a/b", true},
		{"/a/b", "/a/b", true},
		{"/a/*", "/a/b", true},
		{"/a/b", "/a/*", false},
		{"/a/*", "/a/*", true},
		{"/a/*", "/a/b/c", false},
		{"/*/b", "/a/b", true},
		{"/**", "/**", true},
		{"/a/**", "/**", false},
		{"/**", "/a/**", true},
		{"/a/**", "/a/*/**", true},
		{"/a/*/**", "/a/**", false},
		{"/a/**", "/b/c", false},
	}
	for _, tt := range tests {
		if got := pat(t, tt.p).Covers(pat(t, tt.q)); got != tt.want {
			t.Errorf("%s covers %s = %v, want %v", tt.p, tt.q, got, tt.want)
		}
	}
}

func TestZeroIDPatternMatchesNothing(t *testing.T) {
	var zero IDPattern
	if zero.MatchPath("/a") || zero.MatchPath("/") || zero.MatchPath("") {
		t.Error("the zero pattern matched a path")
	}
	if zero.Match(spiffeid.RequireFromPath(td, "/a")) {
		t.Error("the zero pattern matched an ID")
	}
	if Reaches("/", zero) || Reaches("/a", zero) {
		t.Error("a scope reached the zero pattern")
	}
	if zero.Covers(pat(t, "/a")) || pat(t, "/**").Covers(zero) {
		t.Error("the zero pattern covered or was covered")
	}
	if pat(t, "/a").MatchPath("/a/") || pat(t, "/*/b").MatchPath("/../b") {
		t.Error("a pattern matched a non-canonical path")
	}
}
