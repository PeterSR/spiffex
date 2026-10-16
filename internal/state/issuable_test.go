package state

import (
	"crypto/elliptic"
	"strconv"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestIssuable(t *testing.T) {
	key := strconv.Quote(pemKey(t, &ecKey(t, elliptic.P256()).PublicKey))
	r := check(t, `
origins:
  vms:
    provider: keys
    members:
      billing: { keys: [`+key+`] }
  shared:
    provider: keys
    name: ""
    prefix: /shared/box
    members:
      one: { keys: [`+key+`] }
  cluster:
    provider: kubernetes
`)
	wantValid(t, r)
	tests := map[string]bool{
		"spiffe://example.org/vms/billing":                  true,
		"spiffe://example.org/vms/orders":                   false,
		"spiffe://example.org/vms":                          false,
		"spiffe://example.org/shared/box":                   true,
		"spiffe://example.org/shared/box/one":               false,
		"spiffe://example.org/cluster/ns/shop/sa/billing":   true,
		"spiffe://example.org/cluster/anything/at/all":      true,
		"spiffe://example.org/clusters/ns/shop/sa/billing":  false,
		"spiffe://example.com/vms/billing":                  false,
		"spiffe://example.org/elsewhere/ns/shop/sa/billing": false,
	}
	for s, want := range tests {
		if got := Issuable(r.Origins, td, spiffeid.RequireFromString(s)); got != want {
			t.Errorf("%s issuable: %v, want %v", s, got, want)
		}
	}
}
