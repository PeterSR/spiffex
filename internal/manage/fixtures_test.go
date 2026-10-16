package manage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// upstreamJWKS is the inline key set of the test's jwt providers.
var upstreamJWKS = sync.OnceValue(func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	data, err := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "upstream", Algorithm: "ES256", Use: "sig"}.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return `{"keys": [` + string(data) + `]}`
})

// people is the state most tests start from. Everyone is a member of the
// keys origin people, so spiffe://example.org/people/<name> is issuable:
//
//   - alice holds everything on /;
//   - bob holds read, write and delegate on /team;
//   - carol may read /team;
//   - dave holds nothing;
//   - erin may read and delegate on /team, but not write;
//   - frank may write /team/a;
//   - gil may write /zone/inner, inside the origin zone he may not read;
//   - pat may write /team and /secret, so bob may not read pat's grant.
func people(_, pemKey string) string {
	return fmt.Sprintf(`
origins:
  people:
    provider: keys
    members:
      alice: { keys: [%[1]s] }
      bob: { keys: [%[1]s] }
      carol: { keys: [%[1]s] }
      dave: { keys: [%[1]s] }
      erin: { keys: [%[1]s] }
      frank: { keys: [%[1]s] }
      gil: { keys: [%[1]s] }
      pat: { keys: [%[1]s] }
  team-a:
    provider: keys
    prefix: /team/a
  secret:
    provider: keys
    prefix: /secret
  zone:
    provider: keys
    prefix: /zone
  partner:
    provider: partner
    prefix: /partners/acme
providers:
  partner:
    proof:
      jwt: { issuer: https://idp.example.com, jwks: %[2]s, shared: false }
    name: "{sub}"
  custom-audience:
    proof:
      jwt: { issuer: https://idp.example.com, audience: https://api.example.com, jwks: %[2]s, shared: false }
    name: "{sub}"
  verified:
    proof:
      exec: { command: [%[3]s], shared: false }
    name: "{sub}"
grants:
  root: { who: spiffe://example.org/people/alice, can: [read, write, delegate], on: [/] }
  teams: { who: spiffe://example.org/people/bob, can: [read, write, delegate], on: [/team] }
  readers: { who: spiffe://example.org/people/carol, can: [read], on: [/team] }
  stewards: { who: spiffe://example.org/people/erin, can: [read, delegate], on: [/team] }
  writers: { who: spiffe://example.org/people/frank, can: [write], on: [/team/a] }
  zone-inner: { who: spiffe://example.org/people/gil, can: [write], on: [/zone/inner] }
  platform: { who: spiffe://example.org/people/pat, can: [write], on: [/team, /secret] }
`, pemKey, upstreamJWKS(), verifierCommand)
}
