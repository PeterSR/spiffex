package state

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// widestGrants is a state at the limits of SPEC section 6.1: the most
// grants, each with the most scopes, all writing where the ** patterns of
// the others live, so that every grant reaches every other and closure has
// the most to do.
func widestGrants(t testing.TB, closed bool) *State {
	var b strings.Builder
	b.WriteString("grants:\n")
	for i := range MaxGrants {
		var scopes []string
		for j := range MaxScopesPerGrant {
			scopes = append(scopes, fmt.Sprintf("/t%d/s%d/x%d", j%4, (i+j)%32, i))
		}
		can := "[write]"
		if closed {
			can = "[read, write, delegate]"
			scopes[0] = "/"
		}
		fmt.Fprintf(&b, "  g%d: { who: \"spiffe://example.org/t%d/**\", can: %s, on: [%s] }\n", i, i%4, can, strings.Join(scopes, ", "))
	}
	st, err := ParseState([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestClosureCostAtTheLimits(t *testing.T) {
	budget := 500 * time.Millisecond
	if raceEnabled {
		budget = 5 * time.Second
	}
	for _, closed := range []bool{true, false} {
		st := widestGrants(t, closed)
		start := time.Now()
		r := Validate(st, testSettings())
		if took := time.Since(start); took > budget {
			t.Errorf("closed=%v: validating took %s, want under %s", closed, took, budget)
		}
		switch {
		case closed && len(r.Problems) > 0:
			t.Errorf("closed grants have problems: %v", r.Problems[0])
		case !closed && len(r.Problems) != maxClosureProblems+1:
			t.Errorf("open grants: %d problems, want %d and a count of the rest", len(r.Problems), maxClosureProblems+1)
		}
	}
	// One grant more, or one scope more, is refused before closure runs.
	st := widestGrants(t, true)
	st.Grants["one-more"] = &Grant{Who: "spiffe://example.org/x", Can: []string{"read"}, On: []string{"/"}}
	if r := Validate(st, testSettings()); len(r.Problems) == 0 {
		t.Error("257 grants were accepted")
	}
	st = widestGrants(t, true)
	st.Grants["g0"].On = append(st.Grants["g0"].On, "/one/more")
	if r := Validate(st, testSettings()); len(r.Problems) == 0 {
		t.Error("17 scopes were accepted")
	}
}

func BenchmarkClosureAtTheLimits(b *testing.B) {
	st := widestGrants(b, false)
	for b.Loop() {
		Validate(st, testSettings())
	}
}
