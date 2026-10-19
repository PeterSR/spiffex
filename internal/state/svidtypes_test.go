package state

import (
	"slices"
	"testing"
)

func TestEffectiveSVIDTypes(t *testing.T) {
	both := []string{"jwt", "x509"}
	tests := []struct {
		name       string
		origin     []string
		provider   []string
		restricted bool
		want       []string
	}{
		{"nothing set", nil, nil, false, both},
		{"provider default", nil, []string{"x509"}, false, []string{"x509"}},
		{"origin replaces provider", []string{"jwt"}, []string{"x509"}, false, []string{"jwt"}},
		{"origin alone", []string{"x509"}, nil, false, []string{"x509"}},
		{"restricted, nothing set", nil, nil, true, []string{"jwt"}},
		{"restricted, provider default does not apply", nil, both, true, []string{"jwt"}},
		{"restricted, provider x509 does not apply", nil, []string{"x509"}, true, []string{"jwt"}},
		{"restricted, origin lists x509", []string{"jwt", "x509"}, nil, true, both},
		{"restricted, origin lists x509 over provider", []string{"x509"}, []string{"jwt"}, true, []string{"x509"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EffectiveSVIDTypes(tt.origin, tt.provider, tt.restricted); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// The restriction in effect is the origin's own or its provider's, and an
// empty one after expansion still counts.
func TestExpandedSVIDTypes(t *testing.T) {
	r := check(t, `
providers:
  p: { proof: { keys: {} }, svid_types: [jwt, x509], audiences: [orders] }
  q: { proof: { keys: {} }, svid_types: [x509] }
  e: { params: { auds: { type: list, default: [] } }, proof: { keys: {} }, audiences: $auds, svid_types: [jwt, x509] }
origins:
  empty: { provider: e }
  by-provider: { provider: p }
  by-origin: { provider: q, audiences: [orders] }
  plain: { provider: q }
  open: { provider: keys }
`)
	wantValid(t, r)
	if got := r.X509UnderRestriction(); len(got) != 0 {
		t.Errorf("x509 under a restriction: %v, want none", got)
	}
	for name, want := range map[string][]string{
		"empty":       {"jwt"},
		"by-provider": {"jwt"},
		"by-origin":   {"jwt"},
		"plain":       {"x509"},
		"open":        {"jwt", "x509"},
	} {
		if got := r.Origins[name].SVIDTypes; !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

func TestX509UnderRestriction(t *testing.T) {
	r := check(t, `
origins:
  loud: { provider: keys, audiences: [orders], svid_types: [jwt, x509] }
  quiet: { provider: keys, audiences: [orders] }
  open: { provider: keys }
`)
	wantValid(t, r)
	if got := r.X509UnderRestriction(); !slices.Equal(got, []string{"loud"}) {
		t.Errorf("got %v, want [loud]", got)
	}
}
