package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

var td = spiffeid.RequireTrustDomainFromString("example.org")

func newPolicy(t *testing.T) (*Policy, *strings.Builder) {
	t.Helper()
	var log strings.Builder
	return New(Options{
		Settings: state.DefaultSettings("https://issuer.example.org", td),
		Logger:   slog.New(slog.NewTextHandler(&log, nil)),
	}), &log
}

func snapshot(t *testing.T, version, doc string) *store.Snapshot {
	t.Helper()
	st, err := state.ParseState([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return &store.Snapshot{Version: version, State: st}
}

func publicPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func indent(s string) string {
	return "            " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n            ")
}

func TestApply(t *testing.T) {
	p, _ := newPolicy(t)
	if v := p.Current(); v.Len() != 0 || v.Version != store.Absent {
		t.Fatalf("a new policy serves %d origins at version %q", v.Len(), v.Version)
	}
	doc := `
origins:
  vms:
    provider: keys
    members:
      billing:
        keys:
          - |
` + indent(publicPEM(t)) + `
  kube:
    provider: kubernetes
`
	if err := p.Apply(snapshot(t, "v1", doc)); err != nil {
		t.Fatal(err)
	}
	v := p.Current()
	o, member, keys, ok := v.Member("vms/billing")
	if !ok || o.Name != "vms" || member != "billing" || len(keys) != 1 {
		t.Errorf("Member(vms/billing) = %v %q %v %v", o, member, keys, ok)
	}
	for _, id := range []string{"vms", "vms/nobody", "kube/billing", "nope/billing", "vms/billing/x"} {
		if _, _, _, ok := v.Member(id); ok {
			t.Errorf("Member(%q) found a member", id)
		}
	}
	if got := v.Reached("https://kubernetes.default.svc.cluster.local", []string{"https://issuer.example.org/origins/kube"}); len(got) != 1 || got[0].Keys == nil {
		t.Errorf("Reached = %v", got)
	}
	if _, ok := v.Exec("kube"); ok {
		t.Error("a jwt origin passed for an exec origin")
	}
}

func TestApplyKeepsServingTheLastValidState(t *testing.T) {
	p, log := newPolicy(t)
	if err := p.Apply(snapshot(t, "v1", "origins: { kube: { provider: kubernetes } }\n")); err != nil {
		t.Fatal(err)
	}
	p.Reload(snapshot(t, "v2", "origins: { a: { provider: keys, prefix: /x }, b: { provider: keys, prefix: /x/y } }\n"))
	if v := p.Current(); v.Version != "v1" {
		t.Errorf("serving %q after an invalid state, want v1", v.Version)
	}
	if !strings.Contains(log.String(), "overlaps") || !strings.Contains(log.String(), "in_service=v1") {
		t.Errorf("log:\n%s", log)
	}
	p.Reload(&store.Snapshot{Version: "v3", Problem: io.ErrUnexpectedEOF})
	if v := p.Current(); v.Version != "v1" {
		t.Errorf("serving %q after an unparsable state, want v1", v.Version)
	}
}

// Fetched keys survive a reload that leaves the origin's key source as it
// was, and are dropped when it changes.
func TestApplyKeepsKeyCaches(t *testing.T) {
	p, _ := newPolicy(t)
	const partner = `
providers:
  partner:
    proof: { jwt: { issuer: https://idp.partner.example, jwks_uri: $uri, shared: false } }
    params: { uri: { type: string, default: https://idp.partner.example/keys } }
    name: "{sub}"
origins:
  partner: { provider: partner%s }
`
	keysOf := func() any {
		return p.Current().origins["partner"].Keys
	}
	if err := p.Apply(snapshot(t, "v1", strings.Replace(partner, "%s", "", 1))); err != nil {
		t.Fatal(err)
	}
	first := keysOf()
	if err := p.Apply(snapshot(t, "v2", strings.Replace(partner, "%s", "", 1)+"  vms: { provider: keys }\n")); err != nil {
		t.Fatal(err)
	}
	if keysOf() != first {
		t.Error("an unrelated change dropped the origin's key cache")
	}
	if err := p.Apply(snapshot(t, "v3", strings.Replace(partner, "%s", ", with: { uri: https://idp.partner.example/v2/keys }", 1))); err != nil {
		t.Fatal(err)
	}
	if keysOf() == first {
		t.Error("a new jwks_uri kept the old key cache")
	}
}

// A state that disappears is not taken for an empty one, but an empty
// document is.
func TestApplyRefusesADisappearedState(t *testing.T) {
	p, log := newPolicy(t)
	if err := p.Apply(&store.Snapshot{Version: store.Absent, State: &state.State{}}); err != nil {
		t.Fatalf("no state at startup: %v", err)
	}
	if err := p.Apply(snapshot(t, "v1", "origins: { kube: { provider: kubernetes } }\n")); err != nil {
		t.Fatal(err)
	}
	p.Reload(&store.Snapshot{Version: store.Absent, State: &state.State{}})
	if v := p.Current(); v.Version != "v1" || v.Len() != 1 {
		t.Errorf("serving %q with %d origins after the state disappeared", v.Version, v.Len())
	}
	if !strings.Contains(log.String(), "disappeared") {
		t.Errorf("log:\n%s", log)
	}
	if err := p.Apply(&store.Snapshot{Version: "v2", State: &state.State{}}); err != nil || p.Current().Len() != 0 {
		t.Errorf("an empty document: %v, %d origins", err, p.Current().Len())
	}
}
