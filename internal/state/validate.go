package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/PeterSR/spiffex/providers"
	"github.com/PeterSR/spiffex/schema"
)

// Report is the outcome of validating a state, or a single object.
type Report struct {
	// Problems is empty when the state is valid.
	Problems Problems
	// Skipped names the checks that relate objects to each other, when a
	// single object was validated without a whole state.
	Skipped []string
	// Overrides names the providers in the state that take the place of
	// shipped ones (SPEC section 5).
	Overrides []string
	// Origins holds the expanded origins. It is empty whenever there are
	// problems, so nothing of an invalid state can be acted on.
	Origins map[string]*Expanded
	// Grants holds the grants, parsed. It is empty whenever there are
	// problems.
	Grants []ParsedGrant
}

// Err returns the problems as an error, or nil when there are none.
func (r *Report) Err() error {
	if len(r.Problems) == 0 {
		return nil
	}
	return r.Problems
}

// The checks that need a whole state (SPEC section 6.3).
const (
	checkPrefixOverlap  = "prefix overlap"
	checkAudienceUnique = "uniqueness of upstream issuer and audience"
	checkGrantClosure   = "grant closure"
)

var crossObjectChecks = []string{checkPrefixOverlap, checkAudienceUnique, checkGrantClosure}

// Validate validates a whole state (SPEC section 6.2). It checks the size
// and schema of the state itself, so a state built in Go gets the same
// checks as one that was parsed.
func Validate(st *State, s Settings) *Report {
	return validate(st, s, false)
}

// ValidateProvider validates one provider on its own. When none of its
// parameters is required, it is also expanded as an origin of the same
// name would use it.
func ValidateProvider(name string, p *Provider, s Settings) *Report {
	return validate(&State{Providers: map[string]*Provider{name: p}}, s, true)
}

// ValidateOrigin validates one origin on its own, with the providers it may
// use besides the shipped ones.
func ValidateOrigin(name string, o *Origin, providers map[string]*Provider, s Settings) *Report {
	return validate(&State{Origins: map[string]*Origin{name: o}, Providers: providers}, s, true)
}

func validate(st *State, s Settings, partial bool) *Report {
	checked, err := recheck(st)
	if err != nil {
		var problems Problems
		if !errors.As(err, &problems) {
			problems = Problems{{Message: err.Error()}}
		}
		return &Report{Problems: problems, Origins: map[string]*Expanded{}}
	}
	return newValidator(checked, s, partial).run()
}

// recheck encodes a state as JSON and decodes it again through the size and
// schema checks. The copy it returns is the validator's own: what it was
// given cannot change under it, and has the shapes the schema promises.
func recheck(st *State) (*State, error) {
	if st == nil {
		return nil, errors.New("there is no state")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("the state cannot be encoded as JSON: %w", err)
	}
	if len(data) > MaxStateSize {
		return nil, fmt.Errorf("the state is %d bytes as JSON, more than the %d allowed", len(data), MaxStateSize)
	}
	tree, err := decodeTree(data)
	if err != nil {
		return nil, err
	}
	var out State
	if err := decodeChecked(tree, schema.StateID, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type validator struct {
	settings Settings
	state    *State
	// partial is set when validating single objects: checks that relate
	// objects to each other are then skipped.
	partial  bool
	problems Problems
	seen     map[string]bool
	// calls counts every problem raised, repeats included, so a caller can
	// tell whether its own step failed even when the problem was already
	// reported for another origin using the same provider.
	calls int
}

func newValidator(st *State, s Settings, partial bool) *validator {
	return &validator{settings: s, state: st, partial: partial, seen: map[string]bool{}}
}

func (v *validator) add(path, format string, args ...any) {
	v.addProblem(Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) addProblem(p Problem) {
	v.calls++
	if v.seen[p.String()] {
		return
	}
	v.seen[p.String()] = true
	v.problems = append(v.problems, p)
}

func (v *validator) count() int { return v.calls }

var shippedProviders = sync.OnceValues(func() (map[string]*Provider, error) {
	out := map[string]*Provider{}
	for _, name := range providers.Names() {
		data, _ := providers.Source(name)
		p, err := ParseProvider(data)
		if err != nil {
			return nil, fmt.Errorf("shipped provider %s: %w", name, err)
		}
		out[name] = p
	}
	return out, nil
})

func (v *validator) run() *Report {
	r := &Report{Origins: map[string]*Expanded{}}
	defer func() {
		r.Problems = v.problems
		// Nothing of an invalid state may be acted on.
		if len(r.Problems) > 0 {
			r.Origins = map[string]*Expanded{}
			r.Grants = nil
		}
	}()
	if err := v.settings.Check(); err != nil {
		v.add("settings", "%v", err)
		return r
	}
	shipped, err := shippedProviders()
	if err != nil {
		v.add("", "%v", err)
		return r
	}

	broken := map[string]bool{}
	for _, name := range sortedKeys(v.state.Providers) {
		path := field("providers", name)
		p := v.state.Providers[name]
		if err := checkName(name); err != nil {
			v.add(path, "%v", err)
		}
		_, isShipped := shipped[name]
		switch {
		case isShipped && !p.Overrides:
			v.add(path, "a shipped provider is named %s; set overrides: true to take its place", name)
		case !isShipped && p.Overrides:
			v.add(field(path, "overrides"), "no shipped provider is named %s", name)
		case isShipped:
			r.Overrides = append(r.Overrides, name)
		}
		if !v.checkProvider(path, p) {
			broken[name] = true
		}
	}

	for _, name := range sortedKeys(v.state.Origins) {
		path := field("origins", name)
		o := v.state.Origins[name]
		if err := checkName(name); err != nil {
			v.add(path, "%v", err)
			continue
		}
		p, providerPath := v.state.Providers[o.Provider], field("providers", o.Provider)
		if p == nil {
			p, providerPath = shipped[o.Provider], ""
		}
		if p == nil {
			v.add(field(path, "provider"), "no provider named %s in the state or shipped", o.Provider)
			continue
		}
		if broken[o.Provider] {
			continue
		}
		x := &expansion{v: v, name: name, path: path, providerName: o.Provider, providerPath: providerPath}
		if e := x.expand(o, p); e != nil {
			r.Origins[name] = e
		}
	}

	if v.partial && len(v.state.Origins) == 0 {
		v.checkProvidersAlone(r, broken)
	}

	grants := v.checkGrants()
	if v.partial {
		r.Skipped = append(slices.Clone(crossObjectChecks), r.Skipped...)
		return r
	}
	v.checkPrefixes(r.Origins)
	v.checkAudiences(r.Origins)
	if grants != nil {
		v.checkClosure(grants)
		r.Grants = grants
	}
	return r
}

// checkProvidersAlone expands each provider checked on its own as if an
// origin of the same name used it with its defaults, so that rules about
// the expanded proof (files, hosts, executables, the issuer's own URL) are
// checked too.
// Whether a shared upstream's owner is pinned depends on the origin and is
// left out.
func (v *validator) checkProvidersAlone(r *Report, broken map[string]bool) {
	for _, name := range sortedKeys(v.state.Providers) {
		p := v.state.Providers[name]
		if broken[name] {
			continue
		}
		var required []string
		for _, param := range sortedKeys(p.Params) {
			if p.Params[param].Required {
				required = append(required, param)
			}
		}
		if len(required) > 0 {
			r.Skipped = append(r.Skipped, fmt.Sprintf("the expanded checks of provider %s, which need values for its required parameters %v", name, required))
			continue
		}
		path := field("providers", name)
		x := &expansion{v: v, name: name, path: path, providerName: name, providerPath: path, synthetic: true}
		x.expand(&Origin{Provider: name}, p)
		if mayBeShared(p) {
			r.Skipped = append(r.Skipped, fmt.Sprintf("whether origins using provider %s pin the owner, which depends on each origin's match", name))
		}
	}
}

// checkPrefixes refuses overlapping prefixes (SPEC section 4.1).
func (v *validator) checkPrefixes(origins map[string]*Expanded) {
	names := sortedKeys(origins)
	for i, a := range names {
		for _, b := range names[i+1:] {
			if overlap(origins[a].Prefix, origins[b].Prefix) {
				v.add(field("origins", b), "prefix %s overlaps prefix %s of origin %s", origins[b].Prefix, origins[a].Prefix, a)
			}
		}
	}
}

// checkAudiences refuses two jwt origins with the same upstream issuer and
// audience, so that a subject token names at most one origin (SPEC
// section 3.3).
func (v *validator) checkAudiences(origins map[string]*Expanded) {
	type key struct{ issuer, audience string }
	taken := map[key]string{}
	for _, name := range sortedKeys(origins) {
		j := origins[name].JWT
		if j == nil {
			continue
		}
		k := key{j.Issuer, j.Audience}
		if other, dup := taken[k]; dup {
			v.add(field("origins", name), "origin %s already takes tokens from %s with audience %s", other, j.Issuer, j.Audience)
			continue
		}
		taken[k] = name
	}
}

// mayBeShared reports whether origins using the provider could have to pin
// an owner, as far as the provider alone tells.
func mayBeShared(p *Provider) bool {
	if e := p.Proof.Exec; e != nil {
		return e.Shared
	}
	if j := p.Proof.JWT; j != nil {
		_, isRef := paramRef(j.Issuer)
		_, wellKnown := wellKnownOwnerClaims(j.Issuer)
		return j.Shared || isRef || wellKnown
	}
	return false
}

// Shipped returns the provider of that name that ships with spiffex. It is
// shared and must not be changed.
func Shipped(name string) (*Provider, bool) {
	shipped, err := shippedProviders()
	if err != nil {
		return nil, false
	}
	p, ok := shipped[name]
	return p, ok
}
