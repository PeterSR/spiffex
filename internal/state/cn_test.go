package state

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/PeterSR/spiffex/internal/nametemplate"
)

func originCN(t *testing.T, r *Report, name, id string) string {
	t.Helper()
	e := r.Origins[name]
	if e == nil {
		t.Fatalf("no origin %s; problems: %v", name, r.Problems)
	}
	path := strings.TrimPrefix(id, "spiffe://"+td.Name())
	cn, err := e.CommonName(id, path)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cn
}

func TestCommonNameDefault(t *testing.T) {
	r := check(t, `
origins:
  web: { provider: keys }
`)
	wantValid(t, r)
	if got := originCN(t, r, "web", "spiffe://example.org/web/a"); got != "spiffe://example.org/web/a" {
		t.Errorf("default CN = %q", got)
	}
	long := "spiffe://example.org/web/" + strings.Repeat("a", 60)
	if got := originCN(t, r, "web", long); got != "" {
		t.Errorf("a long ID gave CN %q, want none", got)
	}
	if r.Origins["web"].X509CN != nil || r.Origins["web"].X509CNOwn {
		t.Error("the default has a template")
	}
}

func TestCommonNameTemplates(t *testing.T) {
	r := check(t, `
providers:
  p: { proof: { keys: {} }, name: "{member}", x509: { cn: "prov:{path|trim_prefix:/prov/}" } }
origins:
  tenants:
    provider: keys
    prefix: /tenants
    x509: { cn: "tenant:{path|trim_prefix:/tenants/}" }
  hashed:
    provider: keys
    x509: { cn: "{path|hash:24}" }
  lit:
    provider: keys
    x509: { cn: "pg:{spiffe_id|trim_prefix:spiffe://example.org/}" }
  prov:
    provider: p
    prefix: /prov
  plain:
    provider: keys
`)
	wantValid(t, r)
	if got := originCN(t, r, "tenants", "spiffe://example.org/tenants/kokkenogco/backend"); got != "tenant:kokkenogco/backend" {
		t.Errorf("tenants: %q", got)
	}
	if got := originCN(t, r, "hashed", "spiffe://example.org/hashed/a"); got != nametemplate.HashValue("/hashed/a", 24) {
		t.Errorf("hashed: %q", got)
	}
	if got := originCN(t, r, "lit", "spiffe://example.org/lit/a"); got != "pg:lit/a" {
		t.Errorf("lit: %q", got)
	}
	if got := originCN(t, r, "prov", "spiffe://example.org/prov/a"); got != "prov:a" {
		t.Errorf("prov, from its provider's default: %q", got)
	}
	if e := r.Origins["prov"]; e.X509CNOwn || e.X509CN == nil {
		t.Errorf("prov: own = %v, template = %v", e.X509CNOwn, e.X509CN)
	}
	if !r.Origins["tenants"].X509CNOwn {
		t.Error("tenants does not own its template")
	}
	// An error from the template is an error, never a CN left out.
	e := r.Origins["tenants"]
	if cn, err := e.CommonName("spiffe://example.org/tenants/"+strings.Repeat("a", 70), "/tenants/"+strings.Repeat("a", 70)); err == nil {
		t.Errorf("a name of 70 characters gave CN %q", cn)
	}
	if cn, err := e.CommonName("spiffe://example.org/other/a", "/other/a"); err == nil {
		t.Errorf("a path outside the trim gave CN %q", cn)
	}
}

func TestCommonNameProblems(t *testing.T) {
	long := "/" + strings.Repeat("a", 60)
	tests := []struct {
		name, doc, path, msg string
	}{
		{"not a template", `origins: { a: { provider: keys, x509: { cn: "fixed" } } }`, "origins.a.x509.cn", "needs a placeholder"},
		{"a claim", `origins: { a: { provider: keys, x509: { cn: "{sub}" } } }`, "origins.a.x509.cn", "placeholder is"},
		{"unknown operation", `origins: { a: { provider: keys, x509: { cn: "{path|lower:x}" } } }`, "origins.a.x509.cn", "unknown operation"},
		{"bad hash length", `origins: { a: { provider: keys, x509: { cn: "{path|hash:8}" } } }`, "origins.a.x509.cn", "from 24 to 52"},
		{"hash not last", `origins: { a: { provider: keys, x509: { cn: "{path|hash:24|trim_prefix:x}" } } }`, "origins.a.x509.cn", "last operation"},
		{"trim that never applies", `origins: { a: { provider: keys, prefix: /tenants, x509: { cn: "{path|trim_prefix:/other/}" } } }`, "origins.a.x509.cn", "can never apply"},
		{"trim of a whole path", `origins: { a: { provider: keys, name: "", prefix: /tenants, x509: { cn: "{path|trim_prefix:/tenants}" } } }`, "origins.a.x509.cn", "can never apply"},
		// PostgreSQL reads a pg_ident system user that starts with / as a regex.
		{"a bare path", `origins: { a: { provider: keys, x509: { cn: "{path}" } } }`, "origins.a.x509.cn", "can start with /"},
		{"a path with a suffix trimmed", `origins: { a: { provider: keys, x509: { cn: "{path|trim_suffix:/x}" } } }`, "origins.a.x509.cn", "can start with /"},
		{"a prefix trimmed short of the slash", `origins: { a: { provider: keys, prefix: /tenants, x509: { cn: "{path|trim_prefix:/tenants}" } } }`, "origins.a.x509.cn", "can start with /"},
		{"a trim that reaches into the name", `origins: { a: { provider: keys, prefix: /tenants, x509: { cn: "{path|trim_prefix:/tenants/x}" } } }`, "origins.a.x509.cn", "can start with /"},
		{"text that starts with /", `origins: { a: { provider: keys, x509: { cn: "/b{path}" } } }`, "origins.a.x509.cn", "must not start with /"},
		{"a bare path in a provider's default", `
providers: { p: { proof: { keys: {} }, name: "{member}", x509: { cn: "{path}" } } }
origins: { a: { provider: p } }`, "providers.p.x509.cn", "can start with /"},
		{"too long", `origins: { a: { provider: keys, prefix: ` + long + `, x509: { cn: "{spiffe_id}" } } }`, "origins.a.x509.cn", "at least"},
		{"hash and text too long", `origins: { a: { provider: keys, x509: { cn: "` + strings.Repeat("a", 20) + `{path|hash:52}" } } }`, "origins.a.x509.cn", "at least 72"},
		{"unknown key", `origins: { a: { provider: keys, x509: { common_name: "{path}" } } }`, "origins.a", "common_name"},
		{"empty", `origins: { a: { provider: keys, x509: { cn: "" } } }`, "origins.a.x509.cn", ""},
		{"provider syntax", `providers: { p: { proof: { keys: {} }, x509: { cn: "{nope}" } } }`, "providers.p.x509.cn", "placeholder is"},
		{"provider default that cannot apply", `
providers: { p: { proof: { keys: {} }, name: "{member}", x509: { cn: "{path|trim_prefix:/tenants/}" } } }
origins: { a: { provider: p } }`, "providers.p.x509.cn", "can never apply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := ParseState([]byte(tt.doc))
			if err != nil {
				// The schema refused it, which is also a refusal.
				if tt.name != "empty" && tt.name != "unknown key" {
					t.Fatalf("parse: %v", err)
				}
				return
			}
			r := Validate(st, testSettings())
			if tt.name == "a bare path" {
				// A hand-written pg_ident line for /tenants/x/backend would also
				// match /zz/tenants/x/backend, were both names allowed.
				if len(r.Origins) != 0 {
					t.Error("the origin was accepted")
				}
			}
			wantProblem(t, r, tt.path, tt.msg)
		})
	}
}

// A provider's default cannot be judged without a prefix, so a provider
// alone is checked for syntax only.
func TestCommonNameProviderAlone(t *testing.T) {
	p, err := ParseProvider([]byte(`{"proof": {"keys": {}}, "name": "{member}", "x509": {"cn": "{path|trim_prefix:/tenants/}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	wantValid(t, ValidateProvider("p", p, testSettings()))
}

func TestCommonNameAcrossOrigins(t *testing.T) {
	tests := []struct {
		name  string
		doc   string
		clash bool
	}{
		{"defaults", `
origins:
  a: { provider: keys }
  b: { provider: keys }
  ab: { provider: keys }`, false},
		{"paths", `
origins:
  a: { provider: keys, x509: { cn: "a:{path}" } }
  b: { provider: keys, x509: { cn: "b:{path}" } }
  c: { provider: keys }`, false},
		{"own prefix trimmed next to defaults", `
origins:
  tenants: { provider: keys, prefix: /tenants, x509: { cn: "{path|trim_prefix:/tenants/}" } }
  web: { provider: keys }
  api: { provider: keys, x509: { cn: "api:{path}" } }`, false},
		{"own prefix trimmed next to a hash", `
origins:
  tenants: { provider: keys, prefix: /tenants, x509: { cn: "{path|trim_prefix:/tenants/}" } }
  hashed: { provider: keys, x509: { cn: "{path|hash:24}" } }`, true},
		{"own prefix trimmed next to a hash with text", `
origins:
  tenants: { provider: keys, prefix: /tenants, x509: { cn: "t:{path|trim_prefix:/tenants/}" } }
  hashed: { provider: keys, x509: { cn: "{path|hash:24}" } }`, false},
		{"own prefix trimmed and suffix trimmed next to defaults", `
origins:
  tenants: { provider: keys, prefix: /tenants, name: "{member}/backend", x509: { cn: "{path|trim_prefix:/tenants/|trim_suffix:/backend}" } }
  web: { provider: keys }
  api: { provider: keys, x509: { cn: "api:{path}" } }`, false},
		{"two trimmed prefixes", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/}" } }`, true},
		{"two trimmed prefixes with different text", `
origins:
  a: { provider: keys, x509: { cn: "a:{path|trim_prefix:/a/}" } }
  b: { provider: keys, x509: { cn: "b:{path|trim_prefix:/b/}" } }`, false},
		{"text that is not unique", `
origins:
  a: { provider: keys, x509: { cn: "pg:{path|trim_prefix:/a/}" } }
  b: { provider: keys, x509: { cn: "pg:{path|trim_prefix:/b/}" } }`, true},
		{"text that ends where the other's value starts", `
origins:
  b: { provider: keys, name: "", x509: { cn: "{path|trim_prefix:/}" } }
  c: { provider: keys, x509: { cn: "b{path}" } }`, false},
		{"a prefix that spells another origin's path", `
origins:
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/}" } }
  c: { provider: keys, x509: { cn: "b{path}" } }`, true},
		{"same hash", `
origins:
  a: { provider: keys, x509: { cn: "{path|hash:24}" } }
  b: { provider: keys, x509: { cn: "{path|hash:24}" } }`, false},
		{"hash of trimmed values", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|hash:24}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/|hash:24}" } }`, true},
		{"hash of trimmed values, different text", `
origins:
  a: { provider: keys, x509: { cn: "a-{path|trim_prefix:/a/|hash:24}" } }
  b: { provider: keys, x509: { cn: "b-{path|trim_prefix:/b/|hash:24}" } }`, false},
		{"hash of trimmed values, different length", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|hash:24}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/|hash:25}" } }`, false},
		{"hash of trimmed values, different tails", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|hash:24}.a" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/|hash:24}.b" } }`, false},
		{"hash of trimmed values, text of different length", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|hash:25}" } }
  b: { provider: keys, x509: { cn: "a{path|trim_prefix:/b/|hash:24}" } }`, true},
		{"hashes of different lengths with the same text", `
origins:
  a: { provider: keys, x509: { cn: "{path|hash:24}" } }
  b: { provider: keys, x509: { cn: "{path|hash:25}" } }`, false},
		{"hash next to a path", `
origins:
  a: { provider: keys, x509: { cn: "{path|hash:24}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/}" } }
  c: { provider: keys, x509: { cn: "{spiffe_id}" } }
  d: { provider: keys }`, false},
		{"an origin without x509 is not compared", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/}" }, svid_types: [jwt] }`, false},
		{"empty names", `
origins:
  a: { provider: keys, name: "" }
  ab: { provider: keys, name: "" }
  a-b: { provider: keys, name: "", x509: { cn: "{path|trim_prefix:/}" } }`, false},
		{"suffix trimmed", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|trim_suffix:/x}" } }
  b: { provider: keys, x509: { cn: "{path|trim_prefix:/b/}" } }`, true},
		{"suffix trimmed next to defaults", `
origins:
  a: { provider: keys, x509: { cn: "{path|trim_prefix:/a/|trim_suffix:/x}" } }
  b: { provider: keys }`, false},
		{"suffix trimmed with text", `
origins:
  a: { provider: keys, x509: { cn: "a:{path|trim_suffix:/x}" } }
  b: { provider: keys }`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := check(t, tt.doc)
			if !tt.clash {
				wantValid(t, r)
				return
			}
			if len(r.Problems) == 0 {
				t.Fatal("valid, but the origins' common names can clash")
			}
			for _, p := range r.Problems {
				if !strings.Contains(p.Message, "common names could equal") {
					t.Errorf("unexpected problem: %v", p)
				}
			}
		})
	}
}

func TestCommonNameSkippedForASingleObject(t *testing.T) {
	o, err := ParseOrigin([]byte(`{"provider": "keys", "x509": {"cn": "{path|trim_prefix:/a/}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := ValidateOrigin("a", o, nil, testSettings())
	wantValid(t, r)
	found := false
	for _, s := range r.Skipped {
		found = found || s == checkCommonNames
	}
	if !found {
		t.Errorf("skipped: %v", r.Skipped)
	}
}

func TestX509CNUnused(t *testing.T) {
	r := check(t, `
providers:
  p: { proof: { keys: {} }, x509: { cn: "p:{path}" }, svid_types: [jwt] }
origins:
  unused: { provider: keys, x509: { cn: "p:{path}" }, svid_types: [jwt] }
  used: { provider: keys, x509: { cn: "u:{path}" } }
  by-default: { provider: p }
`)
	wantValid(t, r)
	if got := r.X509CNUnused(); len(got) != 1 || got[0] != "unused" {
		t.Errorf("unused: %v, want [unused]", got)
	}
}

// If the check says two origins cannot clash, no identity of one has the common
// name of an identity of the other. It is tried on many random pairs of
// templates and origins, against the names they really give.
func TestCommonNameDisjointnessIsSound(t *testing.T) {
	const domain = "example.org"
	prefixes := []string{"/a", "/ab", "/a-b", "/b", "/tenants", "/b/c", "/spiffe:", "/"}
	names := []string{"x", "a", "ab", "backend", "x/backend", "a/x", "tenants", "c", "b/c/x", "x/x", "ab/c", "n"}
	leads := []string{"", "", "a", "/", "p:", "/b", "spiffe:", "x", "-"}
	tails := []string{"", "", "-z", ".a"}
	prefixTrims := []string{"/a/", "/ab/", "/a-b/", "/b/", "/tenants/", "/", "/b/c/", "a", "/a", "spiffe://example.org/a/", "spiffe://example.org", "spiffe://example.org/", "spiffe:/", "/spiffe:/"}
	suffixTrims := []string{"/x", "x", "/backend", "c", "/x/backend", "backend"}

	randomTemplate := func(rng *rand.Rand) string {
		var b strings.Builder
		b.WriteString(leads[rng.Intn(len(leads))])
		ph := []string{"path", "spiffe_id"}[rng.Intn(2)]
		b.WriteString("{" + ph)
		for i, n := 0, rng.Intn(3); i < n; i++ {
			if rng.Intn(2) == 0 {
				b.WriteString("|trim_prefix:" + prefixTrims[rng.Intn(len(prefixTrims))])
			} else {
				b.WriteString("|trim_suffix:" + suffixTrims[rng.Intn(len(suffixTrims))])
			}
		}
		if rng.Intn(3) == 0 {
			b.WriteString(fmt.Sprintf("|hash:%d", 24+rng.Intn(3)))
		}
		b.WriteString("}")
		b.WriteString(tails[rng.Intn(len(tails))])
		return b.String()
	}
	type origin struct {
		prefix    string
		emptyName bool
		tmpl      string
		cn        *nametemplate.CN
		form      cnForm
		names     map[string]bool
	}
	randomOrigin := func(rng *rand.Rand) *origin {
		for {
			o := &origin{prefix: prefixes[rng.Intn(len(prefixes))], emptyName: rng.Intn(5) == 0}
			if o.prefix == "/" {
				o.emptyName = false
			}
			if rng.Intn(6) == 0 {
				o.tmpl = "{spiffe_id}"
			} else {
				o.tmpl = randomTemplate(rng)
			}
			cn, err := nametemplate.ParseCN(o.tmpl)
			if err != nil {
				continue
			}
			o.cn = cn
			o.form, _ = formOf(cn, domain, o.prefix, o.emptyName)
			if o.form.mayStartWithSlash() {
				// Validation refuses it; and what it lets through never
				// renders a name that starts with /.
				continue
			}
			o.names = map[string]bool{}
			ids := []string{o.prefix}
			if !o.emptyName {
				ids = nil
				for _, n := range names {
					ids = append(ids, strings.TrimSuffix(o.prefix, "/")+"/"+n)
				}
			}
			for _, path := range ids {
				if out, err := cn.Render("spiffe://"+domain+path, path); err == nil {
					if strings.HasPrefix(out, "/") {
						t.Fatalf("%s on %s gives %q, which starts with /", o.tmpl, o.prefix, out)
					}
					o.names[out] = true
				}
			}
			return o
		}
	}
	rng := rand.New(rand.NewSource(1))
	claimed, proven := 0, 0
	for i := 0; i < 100000; i++ {
		a, b := randomOrigin(rng), randomOrigin(rng)
		if overlap(a.prefix, b.prefix) {
			continue
		}
		claimed++
		if !cnDisjoint(a.form, b.form) {
			continue
		}
		proven++
		for cn := range a.names {
			if b.names[cn] {
				t.Fatalf("judged disjoint, but both give %q:\n  %s on %s (empty name %v)\n  %s on %s (empty name %v)", cn, a.tmpl, a.prefix, a.emptyName, b.tmpl, b.prefix, b.emptyName)
			}
		}
	}
	if proven < claimed/20 {
		t.Errorf("only %d of %d pairs proven disjoint: the check proves too little to mean anything", proven, claimed)
	}
	t.Logf("%d of %d pairs proven disjoint", proven, claimed)
}

// jwt is reserved: an empty object is accepted and any key is refused.
func TestJWTObjectTakesNoKeys(t *testing.T) {
	wantValid(t, check(t, `
providers:
  p: { proof: { keys: {} }, jwt: {} }
origins:
  a: { provider: keys, jwt: {} }
  b: { provider: p }
`))
	for _, doc := range []string{
		`origins: { a: { provider: keys, jwt: { x: 1 } } }`,
		`providers: { p: { proof: { keys: {} }, jwt: { x: 1 } } }`,
	} {
		if _, err := ParseState([]byte(doc)); err == nil {
			t.Errorf("accepted %s", doc)
		}
	}
}
