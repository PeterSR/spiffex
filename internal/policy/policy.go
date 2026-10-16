// Package policy turns the issuer's state into what the token endpoint acts
// on. Each valid version of the state is compiled into an immutable View,
// and the view in service is swapped as a whole, so a request sees one
// version of the state from start to finish. An invalid state is never
// compiled: the issuer keeps serving the last valid one (SPEC section 6.2).
package policy

import (
	"crypto"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/store"
)

// View is one valid version of the state, ready to act on.
type View struct {
	// Version is the stored state's version.
	Version  string
	origins  map[string]*Origin
	expanded map[string]*state.Expanded
	// document is the state as stored, shared: never change it.
	document  *state.State
	grants    []state.ParsedGrant
	overrides []string
}

// Document returns the state document of this version. It is shared and
// must not be changed.
func (v *View) Document() *state.State { return v.document }

// Expanded returns the origins, expanded. The map is shared and must not
// be changed.
func (v *View) Expanded() map[string]*state.Expanded { return v.expanded }

// Grants returns the grants, parsed.
func (v *View) Grants() []state.ParsedGrant { return v.grants }

// Overrides names the providers in the state that take the place of
// shipped ones.
func (v *View) Overrides() []string { return v.overrides }

// Origin is an expanded origin, and for a jwt origin where its keys come
// from.
type Origin struct {
	*state.Expanded
	// Keys verifies the subject tokens of a jwt origin.
	Keys exchange.KeySource
}

// Member looks up a keys origin's member by client id, <origin>/<member>
// (SPEC section 3.2).
func (v *View) Member(clientID string) (o *Origin, member string, keys []crypto.PublicKey, ok bool) {
	name, member, found := strings.Cut(clientID, "/")
	if !found {
		return nil, "", nil, false
	}
	o = v.origins[name]
	if o == nil || o.Kind != state.KindKeys {
		return nil, "", nil, false
	}
	keys, ok = o.Members[member]
	if !ok {
		return nil, "", nil, false
	}
	return o, member, keys, true
}

// Reached returns the jwt origins a subject token reaches by its unverified
// issuer and audiences (SPEC section 3.3).
func (v *View) Reached(iss string, auds []string) []*Origin {
	var out []*Origin
	for _, e := range state.Reached(v.expanded, iss, auds) {
		out = append(out, v.origins[e.Name])
	}
	return out
}

// Exec returns the exec origin of that name.
func (v *View) Exec(name string) (*Origin, bool) {
	o := v.origins[name]
	if o == nil || o.Kind != state.KindExec {
		return nil, false
	}
	return o, true
}

// Len returns the number of origins.
func (v *View) Len() int { return len(v.origins) }

// Options configure a Policy.
type Options struct {
	// Settings are what validation needs from the issuer's settings.
	Settings state.Settings
	// RefusePrivateAddresses refuses key fetches to non-public addresses,
	// except to the hosts in AllowPrivateHosts.
	RefusePrivateAddresses bool
	AllowPrivateHosts      []string
	Logger                 *slog.Logger
}

// Policy holds the view in service.
type Policy struct {
	opts    Options
	current atomic.Pointer[View]
	// mu serialises Apply, so views are compiled one at a time and each
	// builds on the one before.
	mu         sync.Mutex
	generation uint64
}

// New returns a Policy serving the empty state until the first Apply.
func New(opts Options) *Policy {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	p := &Policy{opts: opts}
	p.current.Store(&View{Version: store.Absent, origins: map[string]*Origin{}, expanded: map[string]*state.Expanded{}, document: &state.State{}})
	return p
}

// Current returns the view in service.
func (p *Policy) Current() *View { return p.current.Load() }

// Apply validates a snapshot of the state and, when it is valid, puts it in
// service. When it is not, the view in service stays, and the error lists
// the problems.
func (p *Policy) Apply(snap *store.Snapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apply(snap)
}

// apply is Apply for a caller that holds mu.
func (p *Policy) apply(snap *store.Snapshot) error {
	prev := p.current.Load()
	if snap.Version == prev.Version && snap.Problem == nil && snap.Version != store.Absent {
		return nil
	}
	if snap.Problem != nil {
		return snap.Problem
	}
	// A state that was there and is gone is more likely lost than meant to
	// be emptied, which takes writing an empty document.
	if snap.Version == store.Absent && prev.Version != store.Absent {
		return errors.New("the stored state has disappeared; to empty the issuer, store an empty document")
	}
	report := state.Validate(snap.State, p.opts.Settings)
	if err := report.Err(); err != nil {
		return err
	}
	view := p.compile(snap.Version, snap.State, report, prev)
	p.current.Store(view)
	p.generation++
	for _, name := range report.Overrides {
		p.opts.Logger.Warn("a provider in the state overrides the shipped provider of that name", "provider", name)
	}
	return nil
}

// Advance is Apply for a state written on top of version from: it puts
// snap in service only while from is the version in service. When another
// version was put in service meanwhile, one that may already build on snap,
// it leaves that one and reports false; the next reload takes up whatever
// is stored then.
func (p *Policy) Advance(from string, snap *store.Snapshot) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.Load().Version != from {
		return false, nil
	}
	return true, p.apply(snap)
}

// Generation counts the views put in service. A reload hands back the
// generation it saw before reading the state, so that a state read before
// a write was put in service cannot replace it.
func (p *Policy) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

// Reload is Apply for a state that changed while the issuer runs, read
// when generation was in service. It logs the outcome. When another view
// was put in service since, the snapshot may be older than that view, so it
// is left alone and Reload reports false; it reports true when it took the
// snapshot up or refused it as invalid.
func (p *Policy) Reload(generation uint64, snap *store.Snapshot) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation != generation {
		return false
	}
	before := p.current.Load().Version
	if err := p.apply(snap); err != nil {
		var problems state.Problems
		lines := []string{err.Error()}
		if errors.As(err, &problems) {
			lines = lines[:0]
			for _, pr := range problems {
				lines = append(lines, pr.String())
			}
		}
		p.opts.Logger.Error("the stored state is invalid; keeping the state in service",
			"version", snap.Version, "in_service", before, "problems", strings.Join(lines, "; "))
		return true
	}
	if v := p.current.Load(); v.Version != before {
		p.opts.Logger.Info("state reloaded", "version", v.Version, "origins", v.Len())
	}
	return true
}

func (p *Policy) compile(version string, doc *state.State, report *state.Report, prev *View) *View {
	v := &View{Version: version, origins: map[string]*Origin{}, expanded: report.Origins,
		document: doc, grants: report.Grants, overrides: report.Overrides}
	for name, e := range report.Origins {
		o := &Origin{Expanded: e}
		if e.JWT != nil {
			o.Keys = p.keySource(e, prev)
		}
		v.origins[name] = o
	}
	return v
}

// keySource returns where a jwt origin's keys come from, reusing the
// previous view's source, and with it the cached keys, when the origin
// fetches them the same way as before.
func (p *Policy) keySource(e *state.Expanded, prev *View) exchange.KeySource {
	j := e.JWT
	if j.JWKS != nil {
		return exchange.StaticKeys{Set: j.JWKS}
	}
	if old := prev.origins[e.Name]; old != nil && old.JWT != nil && sameKeySource(old.JWT, j) {
		return old.Keys
	}
	if j.JWKSFile != "" {
		return &exchange.FileKeys{Path: j.JWKSFile}
	}
	remote := &exchange.RemoteKeys{
		URL:                    j.JWKSURI,
		CAFile:                 j.CAFile,
		BearerTokenFile:        j.BearerTokenFile,
		RefusePrivateAddresses: p.opts.RefusePrivateAddresses,
		AllowPrivateHosts:      p.opts.AllowPrivateHosts,
	}
	if j.Discovery {
		remote.URL, remote.Discover = j.Issuer, true
	}
	for _, f := range p.opts.Settings.BearerTokenFiles {
		if f.Path == j.BearerTokenFile {
			remote.BearerHosts, remote.BearerPaths = f.Hosts, f.Paths
		}
	}
	return remote
}

func sameKeySource(a, b *state.ExpandedJWT) bool {
	return a.JWKS == nil && b.JWKS == nil &&
		a.JWKSURI == b.JWKSURI && a.JWKSFile == b.JWKSFile && a.Discovery == b.Discovery &&
		(!a.Discovery || a.Issuer == b.Issuer) &&
		a.CAFile == b.CAFile && a.BearerTokenFile == b.BearerTokenFile
}
