package state

import (
	"strings"
	"testing"
)

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"", "", true},
		{"", "a", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"abc", "ab", false},
		{"*", "", true},
		{"*", "anything", true},
		{"**", "", true},
		{"customer-*", "customer-acme", true},
		{"customer-*", "customer-", true},
		{"customer-*", "customer", false},
		{"customer-*", "xcustomer-a", false},
		{"*-prod", "eu-prod", true},
		{"*-prod", "eu-prod-2", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXcYb", false},
		{"a*a", "a", false},
		{"a*a", "aa", true},
		{"ab*ba", "aba", false},
		{"ab*ba", "abba", true},
		{"*a*a*", "aa", true},
		{"*a*a*", "a", false},
		// Greedy leftmost is right: choosing the first b leaves room for the rest.
		{"*b*bc", "abbbc", true},
		{"a*?", "ab?", true},
		{"a.c", "abc", false},
		{"[ab]", "a", false},
		{"$x", "$x", true},
	}
	for _, tt := range tests {
		if got := Pattern(tt.pattern).Match(tt.value); got != tt.want {
			t.Errorf("Pattern(%q).Match(%q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestPatternExact(t *testing.T) {
	if !Pattern("4711").Exact() || Pattern("47*").Exact() || Pattern("*").Exact() {
		t.Error("Exact is wrong")
	}
}

// Inputs that make a backtracking matcher take exponential or high
// polynomial time must finish at once. A regression shows as a test timeout.
func TestPatternMatchIsLinear(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{strings.Repeat("*a", 30) + "*b", long, false},
		{strings.Repeat("*a", 30) + "*", long, true},
		{"*" + strings.Repeat("a", 1000) + "b*", long, false},
		{strings.Repeat("a*", 5000) + "b", long, false},
		{"*" + strings.Repeat("ab", 1000), strings.Repeat("ab", 1<<18), true},
		{strings.Repeat("*", 1<<16), long, true},
	}
	for i, tt := range tests {
		if got := Pattern(tt.pattern).Match(tt.value); got != tt.want {
			t.Errorf("case %d: got %v, want %v", i, got, tt.want)
		}
	}
}

func BenchmarkPatternAdversarial(b *testing.B) {
	p := Pattern(strings.Repeat("*a", 30) + "*b")
	v := strings.Repeat("a", 1<<16)
	for b.Loop() {
		p.Match(v)
	}
}
