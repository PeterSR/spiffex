// Package rotation holds the rules by which the issuer chooses what to sign
// with and when something published can be forgotten (SPEC section 2.4 for
// the JWT signing keys, section 2.5 for the certificate authority). The
// rules are the same for both, so both use this package.
package rotation

import "time"

// Entry is one candidate in a rotation: a signing key, or a signing CA
// certificate. A slice of entries is ordered by Created, oldest first, and
// the caller breaks ties between equal creation times in a fixed order.
type Entry struct {
	// Created decides which entry is newest.
	Created time.Time
	// Published is the earliest moment verifiers can have learned of what
	// the entry stands for. An entry may start signing once it has been
	// published for the activation delay.
	Published time.Time
	// Exposed marks an entry that must never sign again.
	Exposed bool
	// Earliest, when set, is a time before which the entry cannot have been
	// made, known from what it holds rather than from its name. The fallback
	// that trusts creation times counts an entry as created at the later of
	// Created and Earliest.
	Earliest time.Time
}

func (e Entry) activated(now time.Time, delay time.Duration) bool {
	return !e.Published.Add(delay).After(now)
}

// Candidates returns the indexes of the entries that may sign at now, most
// preferred first, and none when every entry is exposed.
//
// An entry that is not exposed and has been published for at least delay may
// sign, the newest first. When none qualifies, every entry looks recently
// published. That happens when something rewrote all the files at once (a
// Kubernetes Secret update does) and the process then restarted, and in a
// freshly created trust domain. Candidates then trusts creation times and
// returns the entries created at least delay ago, newest first, which after
// a rewrite includes what was signing before it (a creation time can be no
// earlier than Earliest); failing that, every entry
// that is not exposed, oldest first.
func Candidates(entries []Entry, now time.Time, delay time.Duration) []int {
	var out []int
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].Exposed && entries[i].activated(now, delay) {
			out = append(out, i)
		}
	}
	if len(out) > 0 {
		return out
	}
	for i := len(entries) - 1; i >= 0; i-- {
		made := entries[i].Created
		if entries[i].Earliest.After(made) {
			made = entries[i].Earliest
		}
		if !entries[i].Exposed && !made.Add(delay).After(now) {
			out = append(out, i)
		}
	}
	if len(out) > 0 {
		return out
	}
	for i, e := range entries {
		if !e.Exposed {
			out = append(out, i)
		}
	}
	return out
}

// Retired returns the indexes of the entries nobody can need any more:
// those the issuer stopped signing with at least retention ago. An entry
// stops signing when a newer one activates. active is the index of the entry
// signing now; it and everything newer are never retired.
func Retired(entries []Entry, active int, delay, retention time.Duration, now time.Time) []int {
	var retired []int
	for i, e := range entries {
		if i == active || !e.Created.Before(entries[active].Created) {
			break
		}
		// The earliest moment a newer entry could have taken over from e.
		var replaced time.Time
		for _, newer := range entries[i+1:] {
			at := newer.Published.Add(delay)
			if replaced.IsZero() || at.Before(replaced) {
				replaced = at
			}
		}
		if !replaced.Add(retention).After(now) {
			retired = append(retired, i)
		}
	}
	return retired
}
