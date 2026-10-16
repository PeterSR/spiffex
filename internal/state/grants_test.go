package state

import (
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestClosure(t *testing.T) {
	tests := []struct {
		name   string
		grants string
		// refused names the grant and the missing permission, or is empty
		// when the grants are closed.
		refused, msg string
	}{
		{
			// ops may write under /ci, so it can create an origin that
			// issues spiffe://example.org/ci/admin and become admin.
			name: "writing is becoming",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  admin: { who: "spiffe://example.org/ci/admin", can: [read, write, delegate], on: [/] }`,
			refused: "grants.ops",
			msg:     "the who of grant admin; grant admin gives delegate on /, but no single grant gives every identity matching spiffe://example.org/vms/ops delegate on /",
		},
		{
			name: "the writer already holds everything",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [read, write, delegate], on: [/] }
  admin: { who: "spiffe://example.org/ci/admin", can: [read, write, delegate], on: [/] }`,
		},
		{
			name: "the writer holds it through another grant",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  ops-all: { who: "spiffe://example.org/vms/*", can: [read, write, delegate], on: [/] }
  admin: { who: "spiffe://example.org/ci/admin", can: [read], on: [/vms] }`,
		},
		{
			name: "the who it holds through does not cover the writer's",
			grants: `
  ops: { who: "spiffe://example.org/vms/*", can: [write], on: [/ci] }
  ops-one: { who: "spiffe://example.org/vms/ops", can: [read], on: [/] }
  reader: { who: "spiffe://example.org/ci/reader", can: [read], on: [/] }`,
			refused: "grants.ops",
			msg:     "read on /",
		},
		{
			name: "permissions spread over several grants do not count",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  ops-a: { who: "spiffe://example.org/vms/ops", can: [read], on: [/a] }
  ops-b: { who: "spiffe://example.org/vms/ops", can: [read], on: [/b] }
  reader: { who: "spiffe://example.org/ci/reader", can: [read], on: [/] }`,
			refused: "grants.ops",
			msg:     "read on /",
		},
		{
			name: "a scope within one of the holder's scopes",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  ops-read: { who: "spiffe://example.org/vms/ops", can: [read], on: [/customers] }
  reader: { who: "spiffe://example.org/ci/reader", can: [read], on: [/customers/acme] }`,
		},
		{
			name: "a write outside the who's reach",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  admin: { who: "spiffe://example.org/vms/admin", can: [read, write, delegate], on: [/] }`,
		},
		{
			name: "a wildcard who in reach",
			grants: `
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  admin: { who: "spiffe://example.org/*/admin", can: [read], on: [/] }`,
			refused: "grants.ops",
			msg:     "read on /",
		},
		{
			// A grant that writes where its own who lives already holds
			// what it gives, so it reaches itself without breaking closure.
			name: "a grant reaching its own who",
			grants: `
  team: { who: "spiffe://example.org/team/**", can: [read, write], on: [/team] }`,
		},
		{
			// Its holders can create /team/x/y and so hold what x-leads
			// gives, though not every one of them matches x-leads' who.
			name: "a wider who writing a narrower one",
			grants: `
  team: { who: "spiffe://example.org/team/**", can: [write], on: [/team] }
  x-leads: { who: "spiffe://example.org/team/x/*", can: [read], on: [/] }`,
			refused: "grants.team",
			msg:     "read on /",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := check(t, "grants:"+tt.grants)
			if tt.refused == "" {
				wantValid(t, r)
				return
			}
			wantProblem(t, r, tt.refused, tt.msg)
		})
	}
}

// Closure is skipped, not failed, when a single object is checked.
func TestClosureNeedsAWholeState(t *testing.T) {
	r := ValidateOrigin("ci", &Origin{Provider: "keys"}, nil, testSettings())
	if !strings.Contains(strings.Join(r.Skipped, ","), checkGrantClosure) {
		t.Errorf("skipped = %v", r.Skipped)
	}
}

func TestGrantHolds(t *testing.T) {
	g := ParsedGrant{Can: []string{PermRead}, On: []string{"/a", "/b/c"}}
	for path, want := range map[string]bool{"/a": true, "/a/x": true, "/ab": false, "/b": false, "/b/c/d": true} {
		if got := g.Holds(PermRead, path); got != want {
			t.Errorf("read on %s = %v, want %v", path, got, want)
		}
	}
	if g.Holds(PermWrite, "/a") {
		t.Error("read gave write")
	}
}

// Every identity matching a narrower who also matches a wider one, so the
// wider grant's permissions are already held.
func TestClosureCoveredByTheReachedGrant(t *testing.T) {
	wantValid(t, check(t, `
grants:
  team: { who: "spiffe://example.org/team/*", can: [write], on: [/team] }
  deep: { who: "spiffe://example.org/team/**", can: [read], on: [/] }
`))
}

func TestHoldsRefusesNonCanonicalPaths(t *testing.T) {
	g := ParsedGrant{Can: []string{PermWrite}, On: []string{"/vms"}}
	for _, path := range []string{"/vms/../admin", "/vms/", "/vms//x", "/vms/./x", "vms", ""} {
		if g.Holds(PermWrite, path) {
			t.Errorf("write held on %q", path)
		}
	}
	bad := ParsedGrant{Can: []string{PermWrite}, On: []string{"/vms/"}}
	if bad.Holds(PermWrite, "/vms/x") {
		t.Error("a non-canonical scope held a path")
	}
	for _, scope := range []string{"/a/..", "/a/", ""} {
		if Reaches(scope, pat(t, "/**")) {
			t.Errorf("%q reached /**", scope)
		}
	}
}

func TestReadIsImplied(t *testing.T) {
	for _, perm := range []string{PermWrite, PermDelegate} {
		g := ParsedGrant{Can: []string{perm}, On: []string{"/a"}}
		if !g.Holds(PermRead, "/a/b") {
			t.Errorf("%s does not imply read", perm)
		}
		if g.Holds(PermRead, "/b") {
			t.Errorf("%s implied read outside its scope", perm)
		}
	}
	if (ParsedGrant{Can: []string{PermRead}, On: []string{"/"}}).Holds(PermWrite, "/a") {
		t.Error("read implied write")
	}
	if (ParsedGrant{Can: []string{PermWrite}, On: []string{"/"}}).Holds(PermDelegate, "/a") {
		t.Error("write implied delegate")
	}
}

// A grant that gives write or delegate gives read too (SPEC section 8.2), so
// it satisfies closure for a grant that gives read.
func TestClosureCountsImpliedRead(t *testing.T) {
	wantValid(t, check(t, `
grants:
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  ops-delegate: { who: "spiffe://example.org/vms/ops", can: [delegate], on: [/] }
  reader: { who: "spiffe://example.org/ci/reader", can: [read], on: [/ci] }
`))
	wantValid(t, check(t, `
grants:
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/] }
  reader: { who: "spiffe://example.org/ci/reader", can: [read], on: [/ci] }
`))
	// Read implies nothing: a reader cannot stand in for a writer.
	wantProblem(t, check(t, `
grants:
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  ops-read: { who: "spiffe://example.org/vms/ops", can: [read], on: [/] }
  writer: { who: "spiffe://example.org/ci/w", can: [write], on: [/x] }
`), "grants.ops", "write on /x")
}

// A closure problem says which grants and which permission are involved,
// for callers that must tell less than its message does.
func TestClosureGap(t *testing.T) {
	r := check(t, `
grants:
  ops: { who: "spiffe://example.org/vms/ops", can: [write], on: [/ci] }
  admin: { who: "spiffe://example.org/ci/admin", can: [delegate], on: [/] }
`)
	if len(r.Problems) != 1 || r.Problems[0].Closure == nil {
		t.Fatalf("problems %v", r.Problems)
	}
	want := ClosureGap{Writer: "ops", Scope: "/ci", Reached: "admin", Perm: "delegate", On: "/"}
	if *r.Problems[0].Closure != want {
		t.Errorf("gap %+v, want %+v", *r.Problems[0].Closure, want)
	}
}

func TestHolds(t *testing.T) {
	r := check(t, `
grants:
  ops: { who: "spiffe://example.org/vms/*", can: [write], on: [/ci, /cd] }
  reader: { who: "spiffe://example.org/vms/auditor", can: [read], on: [/] }
`)
	wantValid(t, r)
	ops, auditor := spiffeid.RequireFromPath(td, "/vms/ops"), spiffeid.RequireFromPath(td, "/vms/auditor")
	tests := []struct {
		id         spiffeid.ID
		perm, path string
		want       bool
	}{
		{ops, PermWrite, "/ci/x", true},
		{ops, PermRead, "/cd", true},
		{ops, PermWrite, "/c", false},
		{ops, PermDelegate, "/ci", false},
		{auditor, PermRead, "/anything", true},
		{auditor, PermWrite, "/ci", true},
		{spiffeid.RequireFromPath(td, "/vms/ops/x"), PermRead, "/ci", false},
	}
	for _, tc := range tests {
		if got := Holds(r.Grants, tc.id, tc.perm, tc.path); got != tc.want {
			t.Errorf("%s holds %s on %s: %v, want %v", tc.id, tc.perm, tc.path, got, tc.want)
		}
	}
}
