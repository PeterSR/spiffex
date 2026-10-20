package manage

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PeterSR/spiffex/internal/state"
)

func keysOrigin(prefix string) map[string]any {
	return map[string]any{"provider": "keys", "prefix": prefix}
}

func names[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// GET /manage/state returns every provider, and only the origins and grants
// the caller may read.
func TestStateIsFiltered(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	tests := []struct {
		who             string
		origins, grants []string
	}{
		{"/people/alice", []string{"partner", "people", "secret", "team-a", "zone"},
			[]string{"platform", "readers", "root", "stewards", "teams", "writers", "zone-inner"}},
		{"/people/bob", []string{"team-a"}, []string{"readers", "stewards", "teams", "writers"}},
		{"/people/frank", []string{"team-a"}, []string{"writers"}},
		{"/people/dave", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.who, func(t *testing.T) {
			a := h.as(tc.who, http.MethodGet, "/state", nil)
			wantStatus(t, a, http.StatusOK)
			if a.etag() != `"`+h.stored().Version+`"` {
				t.Errorf("ETag %s, want the stored version %q", a.etag(), h.stored().Version)
			}
			var st state.State
			if err := json.Unmarshal(a.body, &st); err != nil {
				t.Fatal(err)
			}
			if got := names(st.Origins); !slices.Equal(got, tc.origins) {
				t.Errorf("origins %v, want %v", got, tc.origins)
			}
			if got := names(st.Grants); !slices.Equal(got, tc.grants) {
				t.Errorf("grants %v, want %v", got, tc.grants)
			}
			if got := names(st.Providers); !slices.Equal(got, []string{"custom-audience", "partner", "verified"}) {
				t.Errorf("providers %v, want all of them", got)
			}
		})
	}
}

// Objects the caller may not read are not found, whether they exist or
// not; writes that collide with them are conflicts.
func TestHiddenObjects(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	bob := "/people/bob"
	for _, path := range []string{"/origins/secret", "/origins/nonexistent", "/grants/root", "/grants/platform", "/grants/nonexistent", "/providers/nonexistent"} {
		wantStatus(t, h.as(bob, http.MethodGet, path, nil), http.StatusNotFound)
	}
	for _, path := range []string{"/origins/secret", "/grants/root", "/origins/secret/members/x", "/origins/nonexistent/members/x"} {
		wantStatus(t, h.as(bob, http.MethodDelete, path, nil), http.StatusNotFound)
	}
	wantStatus(t, h.as(bob, http.MethodGet, "/origins/team-a", nil), http.StatusOK)
	wantStatus(t, h.as(bob, http.MethodGet, "/grants/writers", nil), http.StatusOK)
	wantStatus(t, h.as("/people/dave", http.MethodGet, "/providers/partner", nil), http.StatusOK)

	// A name taken by something bob may not read.
	a := h.as(bob, http.MethodPut, "/origins/secret", keysOrigin("/team/secret"))
	wantStatus(t, a, http.StatusConflict)
	if msg := a.errorBody(t).Error; !strings.Contains(msg, "origin secret exists") {
		t.Errorf("conflict reason %q", msg)
	}
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/root", map[string]any{
		"who": "spiffe://example.org/people/bob", "can": []string{"read"}, "on": []string{"/team"},
	}), http.StatusConflict)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-a/members/m", h.member()), http.StatusCreated)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/secret/members/m", h.member()), http.StatusNotFound)

	// gil may write /zone/inner, but the origin zone owns /zone and gil may
	// not read it: the 409 names only its name and prefix.
	a = h.as("/people/gil", http.MethodPut, "/origins/inner", keysOrigin("/zone/inner/x"))
	wantStatus(t, a, http.StatusConflict)
	if msg := a.errorBody(t).Error; msg != "prefix /zone/inner/x overlaps prefix /zone of origin zone, which you may not read" {
		t.Errorf("conflict reason %q", msg)
	}
	// alice may read zone, so for her the same overlap is a plain 422.
	a = h.as("/people/alice", http.MethodPut, "/origins/inner", keysOrigin("/zone/inner/x"))
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || !strings.Contains(p[0].Message, "prefix /zone overlaps prefix /zone/inner/x of origin inner") {
		t.Errorf("problems %v", p)
	}
}

func TestOriginPermissions(t *testing.T) {
	h := newHarness(t, dirStore(t), people)
	bob, alice := "/people/bob", "/people/alice"

	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-b", keysOrigin("/team/b")), http.StatusCreated)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-b", keysOrigin("/team/b2")), http.StatusOK)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/elsewhere", keysOrigin("/elsewhere")), http.StatusForbidden)
	wantStatus(t, h.as("/people/dave", http.MethodPut, "/origins/team-c", keysOrigin("/team/c")), http.StatusForbidden)
	wantStatus(t, h.as("/people/carol", http.MethodPut, "/origins/team-c", keysOrigin("/team/c")), http.StatusForbidden)
	// Moving an origin takes write on the new prefix as well as the old.
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-b", keysOrigin("/elsewhere")), http.StatusForbidden)
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/team-b", keysOrigin("/elsewhere")), http.StatusOK)
	// Now bob may not read team-b, so he cannot take its name back.
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-b", keysOrigin("/team/b")), http.StatusConflict)
	wantStatus(t, h.as(bob, http.MethodDelete, "/origins/team-a", nil), http.StatusNoContent)
	// frank may write /team/a but holds nothing on /team.
	wantStatus(t, h.as("/people/frank", http.MethodPut, "/origins/team-a", keysOrigin("/team/a")), http.StatusCreated)
	wantStatus(t, h.as("/people/frank", http.MethodDelete, "/origins/team-a", nil), http.StatusNoContent)

	// An exec origin, or one taking tokens for another audience than its
	// origin audience, takes write on /.
	exec := map[string]any{"provider": "verified", "prefix": "/team/v"}
	custom := map[string]any{"provider": "custom-audience", "prefix": "/team/c"}
	for name, o := range map[string]map[string]any{"verified": exec, "custom": custom} {
		a := h.as(bob, http.MethodPut, "/origins/"+name, o)
		wantStatus(t, a, http.StatusForbidden)
		if !strings.Contains(a.errorBody(t).Error, "takes write on /") {
			t.Errorf("%s: reason %q", name, a.errorBody(t).Error)
		}
		wantStatus(t, h.as(alice, http.MethodPut, "/origins/"+name, o), http.StatusCreated)
		// Once it exists, changing it takes write on / as well, even into
		// an origin that would not.
		wantStatus(t, h.as(bob, http.MethodPut, "/origins/"+name, keysOrigin(o["prefix"].(string))), http.StatusForbidden)
		// Removing it takes only write on its prefix.
		wantStatus(t, h.as(bob, http.MethodDelete, "/origins/"+name, nil), http.StatusNoContent)
	}

	// Members.
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/team-a/members/m", h.member()), http.StatusNotFound)
	wantStatus(t, h.as(alice, http.MethodPut, "/origins/team-a", keysOrigin("/team/a")), http.StatusCreated)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-a/members/m", h.member()), http.StatusCreated)
	wantStatus(t, h.as(bob, http.MethodPut, "/origins/team-a/members/m", h.member()), http.StatusOK)
	wantStatus(t, h.as("/people/carol", http.MethodPut, "/origins/team-a/members/n", h.member()), http.StatusForbidden)
	wantStatus(t, h.as("/people/carol", http.MethodDelete, "/origins/team-a/members/m", nil), http.StatusForbidden)
	a := h.as(alice, http.MethodPut, "/origins/partner/members/m", h.member())
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || p[0].Path != "origins.partner" {
		t.Errorf("problems %v", p)
	}
	a = h.as(bob, http.MethodPut, "/origins/team-a/members/m", map[string]any{"keys": []string{"not a key"}})
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) == 0 || !strings.HasPrefix(p[0].Path, "origins.team-a.members.m") {
		t.Errorf("problems %v", p)
	}
	wantStatus(t, h.as(bob, http.MethodDelete, "/origins/team-a/members/nobody", nil), http.StatusNotFound)
	wantStatus(t, h.as(bob, http.MethodDelete, "/origins/team-a/members/m", nil), http.StatusNoContent)
}

func TestProviderPermissions(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	provider := map[string]any{"proof": map[string]any{"keys": map[string]any{}}, "name": "{member}"}
	wantStatus(t, h.as("/people/bob", http.MethodPut, "/providers/machines", provider), http.StatusForbidden)
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/providers/machines", provider), http.StatusCreated)
	wantStatus(t, h.as("/people/dave", http.MethodGet, "/providers/machines", nil), http.StatusOK)
	wantStatus(t, h.as("/people/bob", http.MethodDelete, "/providers/machines", nil), http.StatusForbidden)
	// A provider an origin uses cannot go.
	a := h.as("/people/alice", http.MethodDelete, "/providers/partner", nil)
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || p[0].Path != "origins.partner.provider" {
		t.Errorf("problems %v", p)
	}
	// Taking the place of a shipped provider has to be said.
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/providers/keys", provider), http.StatusUnprocessableEntity)
	// Shipped providers are served too, and say where they come from.
	a = h.as("/people/dave", http.MethodGet, "/providers/github", nil)
	wantStatus(t, a, http.StatusOK)
	if a.header.Get(ProviderSourceHeader) != "shipped" || !strings.Contains(string(a.body), "token.actions.githubusercontent.com") {
		t.Errorf("shipped github: %s %s", a.header.Get(ProviderSourceHeader), a.body)
	}
	if a := h.as("/people/dave", http.MethodGet, "/providers/partner", nil); a.header.Get(ProviderSourceHeader) != "state" || a.header.Get(OverridesHeader) != "" {
		t.Errorf("partner: %v", a.header)
	}
	provider["overrides"] = true
	wantStatus(t, h.as("/people/alice", http.MethodPut, "/providers/keys", provider), http.StatusCreated)
	a = h.as("/people/dave", http.MethodGet, "/providers/keys", nil)
	if a.header.Get(ProviderSourceHeader) != "state" || a.header.Get(OverridesHeader) != "keys" {
		t.Errorf("overriding keys: %v", a.header)
	}
	if got := h.as("/people/dave", http.MethodGet, "/state", nil).header.Get(OverridesHeader); got != "keys" {
		t.Errorf("GET /manage/state marks overrides %q, want keys", got)
	}
	if a := h.as("/people/dave", http.MethodGet, "/providers/github", nil); a.header.Get(OverridesHeader) != "keys" {
		t.Errorf("GET of a provider that overrides nothing marks overrides %q, want every override, keys", a.header.Get(OverridesHeader))
	}
	wantStatus(t, h.as("/people/alice", http.MethodDelete, "/providers/github", nil), http.StatusNotFound)
	wantStatus(t, h.as("/people/alice", http.MethodDelete, "/providers/machines", nil), http.StatusNoContent)
}

func grant(who, can, on string) map[string]any {
	return map[string]any{"who": "spiffe://example.org" + who, "can": strings.Split(can, ","), "on": strings.Split(on, ",")}
}

// No escalation: a grant can only be created, changed or removed by a
// caller holding delegate on its scopes and everything it gives there, in
// its old form and its new.
func TestGrantPermissions(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	bob, erin := "/people/bob", "/people/erin"

	wantStatus(t, h.as(bob, http.MethodPut, "/grants/team-a-readers", grant("/people/dave", "read", "/team/a")), http.StatusCreated)
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/team-a-readers", grant("/people/dave", "read,write", "/team/a")), http.StatusOK)
	a := h.as(bob, http.MethodPut, "/grants/wider", grant("/people/dave", "read", "/elsewhere"))
	wantStatus(t, a, http.StatusForbidden)
	if msg := a.errorBody(t).Error; !strings.Contains(msg, "delegate on /elsewhere") {
		t.Errorf("reason %q", msg)
	}
	// erin may delegate on /team but not write, so she can hand out read,
	// but not write, and cannot touch a grant that gives write.
	wantStatus(t, h.as(erin, http.MethodPut, "/grants/erins", grant("/people/dave", "read", "/team")), http.StatusCreated)
	a = h.as(erin, http.MethodPut, "/grants/erins", grant("/people/dave", "write", "/team"))
	wantStatus(t, a, http.StatusForbidden)
	if msg := a.errorBody(t).Error; !strings.Contains(msg, "write on /team") {
		t.Errorf("reason %q", msg)
	}
	a = h.as(erin, http.MethodPut, "/grants/writers", grant("/people/frank", "read", "/team/a"))
	wantStatus(t, a, http.StatusForbidden)
	if msg := a.errorBody(t).Error; !strings.Contains(msg, "changing grant writers takes write on /team/a") {
		t.Errorf("reason %q", msg)
	}
	wantStatus(t, h.as(erin, http.MethodDelete, "/grants/writers", nil), http.StatusForbidden)
	wantStatus(t, h.as("/people/carol", http.MethodPut, "/grants/carols", grant("/people/dave", "read", "/team")), http.StatusForbidden)
	wantStatus(t, h.as(bob, http.MethodDelete, "/grants/writers", nil), http.StatusNoContent)
	wantStatus(t, h.as(erin, http.MethodDelete, "/grants/erins", nil), http.StatusNoContent)
	// A grant is authorized as written, before it is checked: a malformed
	// scope is never held, and only a caller who holds the rest is told
	// what is wrong with it.
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/broken", grant("/people/dave", "read", "team")), http.StatusForbidden)
	a = h.as(bob, http.MethodPut, "/grants/broken", grant("/people/*/x/**/y", "read", "/team"))
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) == 0 || p[0].Path != "grants.broken.who" {
		t.Errorf("problems %v", p)
	}
	many := grant("/people/dave", "read", strings.Repeat("/team,", 16)+"/team")
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/many", many), http.StatusUnprocessableEntity)
}

// An origin is checked against its prefix before it is expanded: a caller
// who may not write there learns nothing about what else is wrong with it.
func TestOriginAuthorizedBeforeExpansion(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	broken := map[string]any{"provider": "partner", "prefix": "/elsewhere", "with": map[string]any{"nope": "x"}}
	a := h.as("/people/bob", http.MethodPut, "/origins/broken", broken)
	wantStatus(t, a, http.StatusForbidden)
	if len(a.errorBody(t).Problems) > 0 {
		t.Errorf("problems told to a caller without permission: %v", a.errorBody(t).Problems)
	}
	broken["prefix"] = "/team/broken"
	a = h.as("/people/bob", http.MethodPut, "/origins/broken", broken)
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if len(a.errorBody(t).Problems) == 0 {
		t.Error("no problems for a caller who may write the prefix")
	}
}

// A grant change that breaks closure is refused with the grants involved
// and the missing permission, as far as the caller may read them.
func TestClosure(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	bob := "/people/bob"
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/leads", grant("/team/lead", "read,write,delegate", "/team")), http.StatusUnprocessableEntity)

	// pat's grant platform gives write on /team, so a grant for an identity
	// under /team must not give more than pat holds. bob may not read
	// platform: the reason names neither it nor what it lacks.
	a := h.as(bob, http.MethodPut, "/grants/leads", grant("/team/lead", "delegate", "/team"))
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || p[0] != (Problem{Path: "grants", Message: hiddenClosure.Message}) {
		t.Errorf("problems %v, want the one fixed reason", p)
	}
	// alice may read everything and is told everything.
	a = h.as("/people/alice", http.MethodPut, "/grants/leads", grant("/team/lead", "delegate", "/team"))
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || p[0].Path != "grants.platform" ||
		!strings.Contains(p[0].Message, "grant leads gives delegate on /team, but no single grant gives every identity matching spiffe://example.org/people/pat delegate on /team") {
		t.Errorf("problems %v", p)
	}

	// With platform gone, bob's own grant is the writer, and he reads both
	// grants involved.
	wantStatus(t, h.as("/people/alice", http.MethodDelete, "/grants/platform", nil), http.StatusNoContent)
	wantStatus(t, h.as(bob, http.MethodPut, "/grants/leads", grant("/team/lead", "read,write,delegate", "/team")), http.StatusCreated)
	a = h.as(bob, http.MethodPut, "/grants/devs", grant("/team/devs/*", "write", "/team"))
	wantStatus(t, a, http.StatusUnprocessableEntity)
	if p := a.errorBody(t).Problems; len(p) != 1 || p[0].Path != "grants.devs" ||
		!strings.Contains(p[0].Message, "the who of grant leads; grant leads gives delegate on /team, but no single grant gives every identity matching spiffe://example.org/team/devs/* delegate on /team") {
		t.Errorf("problems %v", p)
	}
	if h.stored().State.Grants["devs"] != nil {
		t.Error("the refused grant was stored")
	}
}

// POST /manage/check takes read on /, and validates without fetching or
// storing anything.
func TestCheck(t *testing.T) {
	var fetched atomic.Bool
	h := newHarness(t, fileStore(t), people)
	upstream := h.srv.URL + "/never-fetched"
	h.srv.Config.Handler = wrapHandler(h.srv.Config.Handler, "/never-fetched", func() { fetched.Store(true) })
	proposed := map[string]any{
		"origins": map[string]any{
			"ci": map[string]any{"provider": "oidc", "with": map[string]any{"issuer": upstream}},
			"x":  map[string]any{"provider": "keys", "prefix": "/"},
		},
	}
	wantStatus(t, h.as("/people/bob", http.MethodPost, "/check", proposed), http.StatusForbidden)
	a := h.as("/people/alice", http.MethodPost, "/check", proposed)
	wantStatus(t, a, http.StatusOK)
	var result CheckResult
	if err := json.Unmarshal(a.body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Problems) == 0 {
		t.Errorf("result %+v, want problems", result)
	}
	if a.etag() != "" {
		t.Errorf("check answered with ETag %s", a.etag())
	}
	a = h.as("/people/alice", http.MethodPost, "/check", map[string]any{"grants": map[string]any{}})
	if err := json.Unmarshal(a.body, &result); err != nil || !result.Valid {
		t.Errorf("an empty state: %+v %v", result, err)
	}
	if fetched.Load() {
		t.Error("checking fetched from the upstream")
	}
}

// An origin with an audience restriction that lists x509 is reported, and
// the field is absent otherwise (SPEC section 4.5).
func TestCheckReportsX509UnderRestriction(t *testing.T) {
	h := newHarness(t, fileStore(t), people)
	check := func(origin map[string]any) CheckResult {
		a := h.as("/people/alice", http.MethodPost, "/check", map[string]any{"origins": map[string]any{"web": origin}})
		wantStatus(t, a, http.StatusOK)
		var result CheckResult
		if err := json.Unmarshal(a.body, &result); err != nil {
			t.Fatal(err)
		}
		if !result.Valid {
			t.Fatalf("problems %v", result.Problems)
		}
		return result
	}
	listed := check(map[string]any{"provider": "keys", "audiences": []string{"orders"}, "svid_types": []string{"jwt", "x509"}})
	if len(listed.X509UnderRestriction) != 1 || listed.X509UnderRestriction[0] != "web" {
		t.Errorf("x509_under_restriction = %v, want [web]", listed.X509UnderRestriction)
	}
	for name, origin := range map[string]map[string]any{
		"restricted, JWT only by default": {"provider": "keys", "audiences": []string{"orders"}},
		"unrestricted":                    {"provider": "keys", "svid_types": []string{"jwt", "x509"}},
	} {
		if got := check(origin).X509UnderRestriction; len(got) != 0 {
			t.Errorf("%s: x509_under_restriction = %v", name, got)
		}
	}
	a := h.as("/people/alice", http.MethodPost, "/check", map[string]any{})
	if strings.Contains(string(a.body), "x509_under_restriction") {
		t.Errorf("the field is present when empty: %s", a.body)
	}
}

func wrapHandler(next http.Handler, path string, hit func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			hit()
		}
		next.ServeHTTP(w, r)
	})
}
