package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PeterSR/spiffex/providers"
	"github.com/PeterSR/spiffex/schema"
)

// Every shipped provider is an ordinary provider document: it matches the
// provider schema and passes the same checks as one in the state.
func TestShippedProvidersAreValid(t *testing.T) {
	names := providers.Names()
	for _, want := range []string{"github", "gitlab", "keys", "kubernetes", "oidc"} {
		if _, ok := providers.Source(want); !ok {
			t.Errorf("provider %s is not shipped", want)
		}
	}
	for _, name := range names {
		data, _ := providers.Source(name)
		tree, err := decodeTree(data)
		if err != nil {
			t.Fatal(err)
		}
		if problems := validateSchema(schema.ProviderID, tree); len(problems) > 0 {
			t.Errorf("%s: %v", name, problems)
		}
		p, err := ParseProvider(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Description == "" {
			t.Errorf("%s has no description", name)
		}
		// Under its own name it would need overrides: true, so check it as
		// a state provider of another name.
		r := ValidateProvider("shipped-"+name, p, testSettings())
		wantValid(t, r)
	}
}

func TestShippedProvidersExpandWithDefaults(t *testing.T) {
	r := check(t, `
origins:
  kube: { provider: kubernetes }
  vms: { provider: keys }
`)
	wantValid(t, r)
	k := r.Origins["kube"]
	if k.Kind != KindJWT || k.Prefix != "/kube" || k.Template.String() != "ns/{kubernetes.io/namespace}/sa/{kubernetes.io/serviceaccount/name}" {
		t.Errorf("kubernetes = %+v", k)
	}
	if len(k.Match) != 1 || k.Match[0].Claim != "kubernetes.io/namespace" || len(k.Match[0].Patterns) != 1 || k.Match[0].Patterns[0] != "*" {
		t.Errorf("kubernetes match = %v", k.Match)
	}
	if len(k.Deny) != 1 || k.Deny[0].Patterns[0] != "kube-system" {
		t.Errorf("kubernetes deny = %v", k.Deny)
	}
	j := k.JWT
	if j.Issuer != "https://kubernetes.default.svc.cluster.local" || j.Audience != "https://issuer.example.org/origins/kube" || j.Shared ||
		j.CAFile != ServiceAccountCAFile || j.BearerTokenFile != ServiceAccountTokenFile || j.MaxTokenLifetime != DefaultMaxTokenLifetime {
		t.Errorf("kubernetes proof = %+v", j)
	}
	v := r.Origins["vms"]
	if v.Kind != KindKeys || v.Template.String() != "{member}" || v.JWT != nil {
		t.Errorf("keys = %+v", v)
	}

	r = check(t, `
origins:
  ci: { provider: github, with: { owner_id: "4711", refs: [refs/heads/main] } }
  lab: { provider: gitlab, with: { namespace_id: "42", refs: [main] } }
  google: { provider: oidc, with: { issuer: "https://accounts.google.com", owner_claims: [hd] }, match: { sub: "1234" } }
`)
	wantValid(t, r)
	gh := r.Origins["ci"].JWT
	if gh.Issuer != "https://token.actions.githubusercontent.com" || !gh.Discovery || !gh.Shared {
		t.Errorf("github = %+v", gh)
	}
	// For a well-known issuer, the table's owner claims apply.
	if g := r.Origins["google"].JWT; len(g.OwnerClaims) != 1 || g.OwnerClaims[0] != "sub" {
		t.Errorf("google owner claims = %v", g.OwnerClaims)
	}
}

// The example documents validate against the schemas and the full rules.
func TestExampleDocuments(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := ParseState(read("state.yaml")); err != nil {
		t.Errorf("state.yaml: %v", err)
	}
	o, err := ParseOrigin(read("origin.yaml"))
	if err != nil {
		t.Fatalf("origin.yaml: %v", err)
	}
	wantValid(t, ValidateOrigin("prod", o, nil, testSettings()))
	p, err := ParseProvider(read("provider.yaml"))
	if err != nil {
		t.Fatalf("provider.yaml: %v", err)
	}
	wantValid(t, ValidateProvider("cloud", p, testSettings()))
}
