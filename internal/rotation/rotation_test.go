package rotation

import (
	"slices"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func entry(created time.Duration, published time.Duration, exposed bool) Entry {
	return Entry{Created: t0.Add(created), Published: t0.Add(published), Exposed: exposed}
}

func TestCandidates(t *testing.T) {
	h := time.Hour
	entries := []Entry{entry(0, 0, false), entry(10*h, 10*h, false), entry(20*h, 20*h, false)}
	cases := []struct {
		name string
		now  time.Duration
		want []int
	}{
		{"nothing old enough: the oldest", 30 * time.Minute, []int{0, 1, 2}},
		{"first activated", h, []int{0}},
		{"second published, not active", 10*h + 59*time.Minute, []int{0}},
		{"second active, first still preferred last", 11 * h, []int{1, 0}},
		{"all active", 21 * h, []int{2, 1, 0}},
	}
	for _, c := range cases {
		if got := Candidates(entries, t0.Add(c.now), h); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCandidatesSkipExposed(t *testing.T) {
	h := time.Hour
	entries := []Entry{entry(0, 0, false), entry(10*h, 10*h, true)}
	if got := Candidates(entries, t0.Add(20*h), h); !slices.Equal(got, []int{0}) {
		t.Errorf("an exposed newest entry: %v", got)
	}
	entries[0].Exposed = true
	if got := Candidates(entries, t0.Add(20*h), h); len(got) != 0 {
		t.Errorf("everything exposed: %v", got)
	}
}

// Files rewritten at once look new; creation times say who signed before.
func TestCandidatesFallBackToCreationTimes(t *testing.T) {
	h := time.Hour
	rewritten := t0.Add(10*h + 30*time.Minute)
	entries := []Entry{
		{Created: t0, Published: rewritten},
		{Created: t0.Add(10 * h), Published: rewritten},
	}
	if got := Candidates(entries, rewritten.Add(time.Minute), h); !slices.Equal(got, []int{0}) {
		t.Errorf("only the older was created an hour ago: %v", got)
	}
	if got := Candidates(entries, t0.Add(20*h), h); !slices.Equal(got, []int{1, 0}) {
		t.Errorf("both were: %v", got)
	}
}

func TestRetired(t *testing.T) {
	h := time.Hour
	entries := []Entry{entry(0, 0, false), entry(10*h, 10*h, false), entry(20*h, 20*h, false)}
	now := t0.Add(40 * h)
	// The second entry replaced the first at 11h; the third the second at 21h.
	if got := Retired(entries, 2, h, 5*h, now); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("retired = %v", got)
	}
	if got := Retired(entries, 2, h, 25*h, now); !slices.Equal(got, []int{0}) {
		t.Errorf("with a longer retention: %v", got)
	}
	if got := Retired(entries, 1, h, 5*h, now); !slices.Equal(got, []int{0}) {
		t.Errorf("a newer entry that is not active is never retired: %v", got)
	}
}
