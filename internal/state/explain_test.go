package state

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const explainState = `
origins:
  kube:
    provider: kubernetes
    with: { namespaces: [customer-*, platform] }
  ci:
    provider: github
    with: { owner_id: "4711", refs: [refs/heads/main] }
`

var explainNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func serviceAccountToken(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://kubernetes.default.svc.cluster.local",
		"aud": []string{"https://issuer.example.org/origins/kube"},
		"exp": explainNow.Add(10 * time.Minute).Unix(),
		"iat": explainNow.Unix(),
		"sub": "system:serviceaccount:customer-acme:backend",
		"kubernetes.io": map[string]any{
			"namespace":      "customer-acme",
			"pod":            map[string]any{"name": "backend-7d9f", "uid": "1"},
			"serviceaccount": map[string]any{"name": "backend", "uid": "2"},
		},
	}
	if edit != nil {
		edit(claims)
	}
	return sign(t, claims)
}

func sign(t *testing.T, claims any) string {
	t.Helper()
	key := ecKey(t, elliptic.P256())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func explain(t *testing.T, token string) *Explanation {
	t.Helper()
	st, err := ParseState([]byte(explainState))
	if err != nil {
		t.Fatal(err)
	}
	x, err := explainAt(st, testSettings(), token, explainNow)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestExplainAdmits(t *testing.T) {
	x := explain(t, serviceAccountToken(t, nil))
	if !x.Admitted || x.Origin != "kube" || x.SPIFFEID != "spiffe://example.org/kube/ns/customer-acme/sa/backend" {
		t.Errorf("explanation = %+v", x)
	}
	out := x.String()
	for _, want := range []string{"not verified", "origin:    kube", "admitted:  yes", "spiffe id: spiffe://example.org/kube/ns/customer-acme/sa/backend"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestExplainRefuses(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(map[string]any)
		origin string
		reason string
	}{
		{"unknown issuer", func(c map[string]any) { c["iss"] = "https://elsewhere.example" }, "", "no origin takes tokens from https://elsewhere.example"},
		{"wrong audience", func(c map[string]any) { c["aud"] = "spiffex" }, "", "origin kube wants audience https://issuer.example.org/origins/kube"},
		{"own token", func(c map[string]any) { c["iss"] = testIssuer }, "", "comes from this issuer"},
		{"no iss", func(c map[string]any) { delete(c, "iss") }, "", "no iss claim"},
		{"namespace not matched", func(c map[string]any) {
			c["kubernetes.io"].(map[string]any)["namespace"] = "default"
		}, "kube", `match on kubernetes.io/namespace: "default" matches none of "customer-*", "platform"`},
		{"no pod", func(c map[string]any) {
			delete(c["kubernetes.io"].(map[string]any), "pod")
		}, "kube", "claim kubernetes.io/pod/name is required but has no value"},
		{"service account not a segment", func(c map[string]any) {
			c["kubernetes.io"].(map[string]any)["serviceaccount"] = map[string]any{"name": "a/b"}
		}, "kube", `claim kubernetes.io/serviceaccount/name is "a/b", which is not a valid path segment`},
		{"service account a number", func(c map[string]any) {
			c["kubernetes.io"].(map[string]any)["serviceaccount"] = map[string]any{"name": 1.5}
		}, "kube", "the name needs claim kubernetes.io/serviceaccount/name"},
		{"expired", func(c map[string]any) { c["exp"] = explainNow.Add(-time.Hour).Unix() }, "kube", "the token expired at"},
		{"no iat", func(c map[string]any) { delete(c, "iat") }, "kube", "no iat claim"},
		{"too long-lived", func(c map[string]any) { c["exp"] = explainNow.Add(2 * time.Hour).Unix() }, "kube", "longer than the 1h0m0s (plus 30s) origin kube accepts"},
		{"not yet valid", func(c map[string]any) { c["nbf"] = explainNow.Add(time.Hour).Unix() }, "kube", "not valid before"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := explain(t, serviceAccountToken(t, tt.edit))
			if x.Admitted || x.Origin != tt.origin || x.SPIFFEID != "" {
				t.Errorf("explanation = %+v", x)
			}
			if !strings.Contains(strings.Join(x.Reasons, "\n"), tt.reason) {
				t.Errorf("reasons %q lack %q", x.Reasons, tt.reason)
			}
			if !strings.Contains(x.String(), "admitted:  no") {
				t.Errorf("output:\n%s", x)
			}
		})
	}
}

// Integers match exactly as the token wrote them, so an owner id given as a
// JSON number still pins the owner.
func TestExplainIntegerClaims(t *testing.T) {
	claims := map[string]any{
		"iss":                 "https://token.actions.githubusercontent.com",
		"aud":                 "https://issuer.example.org/origins/ci",
		"exp":                 explainNow.Add(5 * time.Minute).Unix(),
		"iat":                 explainNow.Unix(),
		"repository_owner_id": json.Number("4711"),
		"repository_id":       json.Number("12345678901234567890"),
		"ref":                 "refs/heads/main",
	}
	x := explain(t, sign(t, claims))
	if !x.Admitted || x.SPIFFEID != "spiffe://example.org/ci/12345678901234567890" {
		t.Errorf("explanation = %+v", x)
	}
	claims["repository_owner_id"] = json.Number("4711.0")
	if x := explain(t, sign(t, claims)); x.Admitted {
		t.Error("4711.0 matched 4711")
	}
}

func TestExplainNeedsAValidStateAndAJWT(t *testing.T) {
	st, err := ParseState([]byte("origins: { a: { provider: nope } }"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Explain(st, testSettings(), serviceAccountToken(t, nil)); err == nil {
		t.Error("explained against an invalid state")
	}
	st, _ = ParseState([]byte(explainState))
	for _, token := range []string{"", "not.a.jwt", "eyJhbGciOiJub25lIn0.e30."} {
		if _, err := Explain(st, testSettings(), token); err == nil {
			t.Errorf("explained %q", token)
		}
	}
}

func TestMemberID(t *testing.T) {
	key := pemKey(t, &ecKey(t, elliptic.P256()).PublicKey)
	r := check(t, "origins:\n  vms:\n    provider: keys\n    members:\n      billing: { keys: ["+jsonString(key)+"] }\n  shared:\n    provider: keys\n    name: fleet\n    members:\n      a: { keys: ["+jsonString(key)+"] }\n")
	wantValid(t, r)
	if id, err := r.Origins["vms"].MemberID(td, "billing"); err != nil || id.String() != "spiffe://example.org/vms/billing" {
		t.Errorf("billing = %v, %v", id, err)
	}
	if id, err := r.Origins["shared"].MemberID(td, "a"); err != nil || id.String() != "spiffe://example.org/shared/fleet" {
		t.Errorf("shared = %v, %v", id, err)
	}
	if _, err := r.Origins["vms"].MemberID(td, "nobody"); err == nil {
		t.Error("an unknown member got an ID")
	}
	if _, err := r.Origins["vms"].Admit(td, map[string]any{}); err == nil {
		t.Error("a keys origin admitted a token")
	}
}

func TestAllowsAudience(t *testing.T) {
	e := &Expanded{}
	if !e.AllowsAudience("anything") {
		t.Error("no restriction refused an audience")
	}
	e.Audiences = []Pattern{"https://*.example.org", "sts.amazonaws.com"}
	for aud, want := range map[string]bool{"https://api.example.org": true, "sts.amazonaws.com": true, "https://example.org": false} {
		if got := e.AllowsAudience(aud); got != want {
			t.Errorf("%s allowed = %v, want %v", aud, got, want)
		}
	}
}

func jsonString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// Kubernetes issues 3607-second tokens for an hour's lifetime; the allowance
// admits them.
func TestExplainLifetimeAllowance(t *testing.T) {
	x := explain(t, serviceAccountToken(t, func(c map[string]any) { c["exp"] = explainNow.Add(3607 * time.Second).Unix() }))
	if !x.Admitted {
		t.Errorf("a 3607s token was refused: %v", x.Reasons)
	}
	x = explain(t, serviceAccountToken(t, func(c map[string]any) { c["exp"] = explainNow.Add(3631 * time.Second).Unix() }))
	if x.Admitted {
		t.Error("a token beyond the allowance was admitted")
	}
}

// Admit's error is the same for every refusal; only LogDetail says why.
func TestAdmitKeepsReasonsOutOfTheError(t *testing.T) {
	r := check(t, explainState)
	claims, _ := DecodeClaims([]byte(`{"kubernetes.io": {"namespace": "secret-ns", "pod": {"name": "p"}, "serviceaccount": {"name": "s"}}}`))
	_, err := r.Origins["kube"].Admit(td, claims)
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "secret-ns") || strings.Contains(err.Error(), "customer-") {
		t.Errorf("the error reveals claims or patterns: %s", err)
	}
	if !strings.Contains(refused.LogDetail(), `"secret-ns" matches none of "customer-*", "platform"`) {
		t.Errorf("detail = %s", refused.LogDetail())
	}
}
