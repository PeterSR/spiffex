package state

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Issuable reports whether the origins could still issue id (SPEC
// section 8.1): its path is within the prefix of a jwt or exec origin, or a
// current member of a keys origin has it. For a jwt or exec origin only the
// prefix counts, so narrowing its admission does not make an identity it
// issued before unissuable.
func Issuable(origins map[string]*Expanded, td spiffeid.TrustDomain, id spiffeid.ID) bool {
	if !id.MemberOf(td) {
		return false
	}
	for _, e := range origins {
		if !within(id.Path(), e.Prefix) {
			continue
		}
		if e.Kind != KindKeys {
			return true
		}
		for member := range e.Members {
			if got, err := e.MemberID(td, member); err == nil && got == id {
				return true
			}
		}
	}
	return false
}
