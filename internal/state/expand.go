package state

import (
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Kind is the kind of proof an origin takes.
type Kind string

// The proof kinds (SPEC section 5).
const (
	KindJWT  Kind = "jwt"
	KindKeys Kind = "keys"
	KindExec Kind = "exec"
)

const (
	// DefaultMaxTokenLifetime applies when a jwt proof sets none.
	DefaultMaxTokenLifetime = time.Hour
	maxMaxTokenLifetime     = 24 * time.Hour
	// DefaultExecTimeout applies when an exec proof sets no timeout.
	DefaultExecTimeout = 5 * time.Second
	maxExecTimeout     = 30 * time.Second
	// maxIDLength is the longest SPIFFE ID an origin may issue.
	maxIDLength = 2048
)

// Expanded is an origin combined with its provider and parameters: what the
// issuer acts on.
type Expanded struct {
	Name     string
	Provider string
	Kind     Kind
	// Prefix is never empty; / is the root.
	Prefix   string
	Template Template
	// Require, Match and Deny are the provider's and the origin's together;
	// all of them apply.
	Require []string
	Match   []Condition
	Deny    []Condition
	// Audiences restricts the audiences identities may request. Nil means
	// no restriction.
	Audiences []Pattern
	// JWT is set for a jwt origin.
	JWT *ExpandedJWT
	// Exec is set for an exec origin.
	Exec *ExpandedExec
	// Members are a keys origin's members and their public keys.
	Members map[string][]crypto.PublicKey
}

// Condition is one match or deny entry: it holds when the claim has a value
// matching one of the patterns.
type Condition struct {
	Claim    string
	Patterns []Pattern
}

// ExpandedJWT is a jwt proof with its parameters filled in.
type ExpandedJWT struct {
	Issuer   string
	Audience string
	// OriginAudience is true when Audience is the origin audience. Otherwise
	// only those who may write / can create or change the origin (SPEC
	// section 5.2).
	OriginAudience bool
	// Exactly one of JWKS, JWKSURI, JWKSFile and Discovery says where the
	// upstream's keys are.
	JWKS            *jose.JSONWebKeySet
	JWKSURI         string
	JWKSFile        string
	Discovery       bool
	CAFile          string
	BearerTokenFile string
	// Shared is true when the document says so or the issuer is well known.
	Shared bool
	// OwnerClaims are the claims that name a token's owner: the well-known
	// ones for a well-known issuer, the document's otherwise.
	OwnerClaims      []string
	MaxTokenLifetime time.Duration
}

// ExpandedExec is an exec proof, ready to run.
type ExpandedExec struct {
	Command []string
	// Audience is the origin audience, which the verifier must find named in
	// the proof (SPEC section 5.4).
	Audience string
	Timeout  time.Duration
	Shared   bool
	// OwnerClaims are the claims, among those the verifier returns, that
	// name the proof's owner.
	OwnerClaims []string
	// Params are the origin's parameter values, defaults included. The
	// verifier receives them as data (SPEC section 5.4).
	Params map[string]Strings
}

// OriginAudience returns the default audience of a jwt origin: the issuer
// URL, /origins, and the prefix (SPEC section 5.2).
func OriginAudience(issuer, prefix string) string {
	if prefix == "/" {
		return issuer + "/origins"
	}
	return issuer + "/origins" + prefix
}

func (p *Provider) kind() Kind {
	switch {
	case p.Proof.Keys != nil:
		return KindKeys
	case p.Proof.Exec != nil:
		return KindExec
	}
	return KindJWT
}

// expansion holds what is needed to expand one origin and to say where its
// problems lie.
type expansion struct {
	v    *validator
	name string
	// path is where problems with the origin itself go.
	path         string
	providerName string
	// providerPath is where problems with the provider's own text go. It is
	// empty for a shipped provider, whose text is not in the document.
	providerPath string
	// synthetic is set when a provider is checked on its own, as if an
	// origin of the same name used it with its defaults.
	synthetic bool
	values    map[string]Strings
}

func (x *expansion) originProblem(at, format string, args ...any) {
	x.v.add(at, format, args...)
}

func (x *expansion) paramProblem(param string, err error) {
	x.v.add(field(field(x.path, "with"), param), "%v", err)
}

// providerProblem reports a problem with the provider's text: at the
// provider when it is in the document, and at the origin otherwise.
func (x *expansion) providerProblem(fieldPath []string, err error) {
	if x.providerPath != "" {
		at := x.providerPath
		for _, f := range fieldPath {
			at = field(at, f)
		}
		x.v.add(at, "%v", err)
		return
	}
	x.v.add(field(x.path, "provider"), "shipped provider %s, %s: %v", x.providerName, strings.Join(fieldPath, "."), err)
}

// valueProblem reports a problem with a value that came from param, or from
// the provider's text when param is empty.
func (x *expansion) valueProblem(param string, fieldPath []string, err error) {
	if param != "" {
		x.paramProblem(param, err)
		return
	}
	x.providerProblem(fieldPath, err)
}

// expand combines an origin with its provider. It returns nil when a problem
// keeps the origin from being used.
func (x *expansion) expand(o *Origin, p *Provider) *Expanded {
	start := x.v.count()
	kind := p.kind()
	if !x.params(o, p) {
		return nil
	}
	sub := substituter{values: x.values, report: x.paramProblem}
	e := &Expanded{Name: x.name, Provider: x.providerName, Kind: kind, Prefix: "/" + x.name}

	if o.Prefix != "" {
		if err := checkPrefix(o.Prefix); err != nil {
			x.originProblem(field(x.path, "prefix"), "%v", err)
		}
		e.Prefix = o.Prefix
	}

	templateText := p.Name
	if o.Name != nil {
		templateText = *o.Name
	}
	tmpl, err := ParseTemplate(templateText, kind)
	switch {
	case err != nil && o.Name != nil:
		x.originProblem(field(x.path, "name"), "%v", err)
	case err != nil:
		x.providerProblem([]string{"name"}, err)
	}
	e.Template = tmpl
	if len(tmpl) == 0 && e.Prefix == "/" {
		x.originProblem(x.path, "an origin with prefix / needs a name template, or every identity would be the trust domain itself")
	}

	if kind == KindKeys && (len(o.Require) > 0 || len(o.Match) > 0 || len(o.Deny) > 0) {
		x.originProblem(x.path, "a keys origin has no require, match or deny")
	}
	e.Require = append(slices.Clone(p.Require), o.Require...)
	e.Match = append(sub.conditions(p.Match), literalConditions(o.Match)...)
	e.Deny = append(sub.conditions(p.Deny), literalConditions(o.Deny)...)
	for i, r := range o.Require {
		if err := checkClaimPath(r); err != nil {
			x.originProblem(index(field(x.path, "require"), i), "%v", err)
		}
	}
	x.checkConditions(field(x.path, "match"), o.Match)
	x.checkConditions(field(x.path, "deny"), o.Deny)

	if o.Audiences != nil {
		x.checkPatterns(field(x.path, "audiences"), *o.Audiences)
		e.Audiences = toPatterns(o.Audiences.Values)
	} else if p.Audiences != nil {
		e.Audiences = toPatterns(sub.list(p.Audiences, checkPattern))
	}

	if kind != KindKeys && len(o.Members) > 0 {
		x.originProblem(field(x.path, "members"), "only a keys origin has members, and this is a %s origin", kind)
	}
	switch kind {
	case KindJWT:
		e.JWT = x.expandJWT(e, p.Proof.JWT, sub)
	case KindExec:
		e.Exec = x.expandExec(e, p.Proof.Exec)
	case KindKeys:
		e.Members = x.members(o)
	}

	if id := e.join(x.v.settings.TrustDomain.Name(), tmpl.Shortest()); len(id) > maxIDLength {
		x.originProblem(x.path, "its shortest SPIFFE ID, %s..., is %d bytes, more than the %d allowed", id[:64], len(id), maxIDLength)
	}
	if x.v.count() > start {
		return nil
	}
	return e
}

// checkConditions checks an origin's own match or deny entries.
func (x *expansion) checkConditions(path string, conds map[string]Strings) {
	for _, claim := range sortedKeys(conds) {
		at := field(path, claim)
		if err := checkClaimPath(claim); err != nil {
			x.originProblem(at, "%v", err)
		}
		x.checkPatterns(at, conds[claim])
	}
}

func (x *expansion) checkPatterns(path string, patterns Strings) {
	for i, p := range patterns.Values {
		if err := checkPattern(p); err != nil {
			at := path
			if patterns.List {
				at = index(path, i)
			}
			x.originProblem(at, "%v", err)
		}
	}
}

// params checks the origin's parameter values and fills in defaults.
func (x *expansion) params(o *Origin, p *Provider) bool {
	ok := true
	x.values = map[string]Strings{}
	for _, name := range sortedKeys(o.With) {
		at := field(field(x.path, "with"), name)
		value := o.With[name]
		decl := p.Params[name]
		switch {
		case decl == nil:
			x.originProblem(at, "provider %s has no parameter %s", x.providerName, name)
			ok = false
		case value.List != (decl.Type == ParamList):
			x.originProblem(at, "want a %s", decl.Type)
			ok = false
		default:
			x.values[name] = value
		}
	}
	for _, name := range sortedKeys(p.Params) {
		decl := p.Params[name]
		if _, given := o.With[name]; given {
			continue
		}
		if decl.Required {
			x.originProblem(field(x.path, "with"), "parameter %s of provider %s is required", name, x.providerName)
			ok = false
			continue
		}
		if decl.Default != nil {
			x.values[name] = *decl.Default
		}
	}
	return ok
}

func (x *expansion) expandJWT(e *Expanded, pj *JWTProof, sub substituter) *ExpandedJWT {
	settings := x.v.settings
	j := &ExpandedJWT{
		JWKSFile:         pj.JWKSFile,
		Discovery:        pj.Discovery,
		CAFile:           pj.CAFile,
		BearerTokenFile:  pj.BearerTokenFile,
		MaxTokenLifetime: DefaultMaxTokenLifetime,
	}
	jwtField := func(name string) []string { return []string{"proof", "jwt", name} }

	var issuerParam, audienceParam, uriParam string
	j.Issuer, issuerParam = sub.string(pj.Issuer, checkNonEmpty)
	j.Audience, audienceParam = sub.string(pj.Audience, checkNonEmpty)
	j.JWKSURI, uriParam = sub.string(pj.JWKSURI, checkHTTPSURL)
	j.OwnerClaims = sub.list(pj.OwnerClaims, checkOwnerClaim)
	if pj.JWKS != nil {
		j.JWKS, _ = parseJWKS(pj.JWKS)
	}
	if pj.MaxTokenLifetime != "" {
		j.MaxTokenLifetime, _ = parseDuration(pj.MaxTokenLifetime, maxMaxTokenLifetime)
	}

	originAudience := OriginAudience(settings.Issuer, e.Prefix)
	if j.Audience == "" {
		j.Audience = originAudience
	}
	j.OriginAudience = j.Audience == originAudience

	if strings.TrimSuffix(j.Issuer, "/") == settings.Issuer {
		x.valueProblem(issuerParam, jwtField("issuer"), fmt.Errorf("the issuer cannot be its own upstream"))
	}
	// Any other audience at or under the issuer URL could be one of its
	// endpoints, or another origin's audience.
	if !j.OriginAudience && (strings.TrimSuffix(j.Audience, "/") == settings.Issuer || strings.HasPrefix(j.Audience, settings.Issuer+"/")) {
		x.valueProblem(audienceParam, jwtField("audience"), fmt.Errorf("%s is the issuer URL or under it; the only such audience allowed is the origin audience %s", j.Audience, originAudience))
	}
	if j.Discovery && issuerParam != "" {
		if err := checkHTTPSURL(j.Issuer); err != nil {
			x.paramProblem(issuerParam, fmt.Errorf("discovery needs an https issuer: %w", err))
		}
	}

	if j.JWKSFile != "" && !settings.readable(j.JWKSFile) {
		x.providerProblem(jwtField("jwks_file"), fmt.Errorf("%s is not among the files the issuer's settings allow it to read", j.JWKSFile))
	}
	if j.CAFile != "" && !settings.readable(j.CAFile) {
		x.providerProblem(jwtField("ca_file"), fmt.Errorf("%s is not among the files the issuer's settings allow it to read", j.CAFile))
	}
	if j.BearerTokenFile != "" {
		x.checkBearer(j, issuerParam, uriParam)
	}

	owners, wellKnown := wellKnownOwnerClaims(j.Issuer)
	j.Shared = pj.Shared || wellKnown
	if !wellKnown {
		owners = j.OwnerClaims
	}
	if j.Shared {
		j.OwnerClaims = owners
		if len(owners) == 0 {
			var param string
			if oc := pj.OwnerClaims; oc != nil && !oc.List {
				param, _ = paramRef(oc.Values[0])
			}
			x.valueProblem(param, []string{"proof", "jwt", "owner_claims"}, fmt.Errorf("a shared upstream that is not well known needs owner claims"))
		} else if !x.synthetic {
			what := "a shared upstream"
			if wellKnown {
				what = "a well-known shared upstream"
			}
			x.checkOwnerPinned(e, fmt.Sprintf("%s is %s", j.Issuer, what), owners)
		}
	}
	return j
}

func (x *expansion) expandExec(e *Expanded, pe *ExecProof) *ExpandedExec {
	ex := &ExpandedExec{
		Command:     slices.Clone(pe.Command),
		Audience:    OriginAudience(x.v.settings.Issuer, e.Prefix),
		Timeout:     DefaultExecTimeout,
		Shared:      pe.Shared,
		OwnerClaims: slices.Clone(pe.OwnerClaims),
		Params:      x.values,
	}
	if pe.Timeout != "" {
		ex.Timeout, _ = parseDuration(pe.Timeout, maxExecTimeout)
	}
	if len(pe.Command) > 0 && !x.v.settings.verifier(pe.Command) {
		x.providerProblem([]string{"proof", "exec", "command"}, fmt.Errorf("%q is not among the verifiers installed in the issuer's settings, which must list the command with exactly these arguments", pe.Command))
	}
	if ex.Shared {
		if len(ex.OwnerClaims) == 0 {
			x.providerProblem([]string{"proof", "exec", "owner_claims"}, fmt.Errorf("a shared exec proof needs owner claims"))
		} else if !x.synthetic {
			x.checkOwnerPinned(e, "the verifier accepts proofs anyone can obtain", ex.OwnerClaims)
		}
	}
	return ex
}

// checkBearer makes sure the issuer's own token is only ever sent to a host
// the settings allow it for (SPEC section 5.2).
func (x *expansion) checkBearer(j *ExpandedJWT, issuerParam, uriParam string) {
	f, ok := x.v.settings.bearerTokenFile(j.BearerTokenFile)
	if !ok {
		x.providerProblem([]string{"proof", "jwt", "bearer_token_file"}, fmt.Errorf("this bearer token file is not allowed by the issuer's settings"))
		return
	}
	target, param, fieldName := j.JWKSURI, uriParam, "jwks_uri"
	if j.Discovery {
		target, param, fieldName = strings.TrimSuffix(j.Issuer, "/")+"/.well-known/openid-configuration", issuerParam, "issuer"
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return // reported where the URL is checked
	}
	// The settings are the operator's: say neither which hosts and paths
	// they allow nor anything else about the token file.
	switch {
	case !slices.ContainsFunc(f.Hosts, func(h string) bool { return strings.EqualFold(h, u.Host) }):
		err = fmt.Errorf("the issuer's settings do not allow the bearer token file to be sent to %s", u.Host)
	case len(f.Paths) > 0 && (u.RawQuery != "" || !slices.Contains(f.Paths, u.Path)):
		err = fmt.Errorf("the issuer's settings do not allow the bearer token file to be sent to %s on %s", u.Host, u.Path)
	default:
		return
	}
	if param != "" {
		x.paramProblem(param, err)
		return
	}
	x.providerProblem([]string{"proof", "jwt", fieldName}, err)
}

// checkOwnerPinned enforces that admission of a shared upstream or verifier
// pins the owner with an exact match (SPEC section 5.3).
func (x *expansion) checkOwnerPinned(e *Expanded, why string, owners []string) {
	for _, c := range e.Match {
		if slices.Contains(owners, c.Claim) && len(c.Patterns) > 0 && allExact(c.Patterns) {
			return
		}
	}
	x.originProblem(field(x.path, "match"), "%s: admission needs a match entry with only exact patterns on one of %s", why, strings.Join(owners, ", "))
}

func allExact(patterns []Pattern) bool {
	for _, p := range patterns {
		if !p.Exact() {
			return false
		}
	}
	return true
}

func (x *expansion) members(o *Origin) map[string][]crypto.PublicKey {
	out := make(map[string][]crypto.PublicKey, len(o.Members))
	for _, name := range sortedKeys(o.Members) {
		at := field(field(x.path, "members"), name)
		if err := checkSegment(name); err != nil {
			x.originProblem(at, "a member's name must be a path segment: %v", err)
		}
		m := o.Members[name]
		if len(m.Keys) == 0 || len(m.Keys) > maxMemberKeys {
			x.originProblem(field(at, "keys"), "want 1 to %d keys, not %d", maxMemberKeys, len(m.Keys))
		}
		for i, raw := range m.Keys {
			key, err := parseMemberKey(raw)
			if err != nil {
				x.originProblem(index(field(at, "keys"), i), "%v", err)
				continue
			}
			out[name] = append(out[name], key)
		}
	}
	return out
}

// join builds a SPIFFE ID of the origin from its trust domain and a name.
func (e *Expanded) join(td, name string) string {
	id := "spiffe://" + td
	if e.Prefix != "/" {
		id += e.Prefix
	}
	if name != "" || e.Prefix == "/" {
		id += "/" + name
	}
	return id
}

func checkNonEmpty(s string) error {
	if s == "" {
		return fmt.Errorf("cannot be empty")
	}
	return nil
}

// checkPattern refuses an empty pattern, which would match only a value that
// counts as absent anyway, or a requested audience that can never be valid.
func checkPattern(s string) error {
	if s == "" {
		return fmt.Errorf("a pattern cannot be empty")
	}
	return nil
}

// checkHTTPSURL checks a URL keys are fetched from.
func checkHTTPSURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%q is not a URL", s)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%q must be an https URL with a host and no user information or fragment", s)
	}
	return nil
}

// parseDuration parses a whole number of seconds, minutes or hours, written
// as 90s, 30m or 1h, of at most limit.
func parseDuration(s string, limit time.Duration) (time.Duration, error) {
	units := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour}
	bad := fmt.Errorf("%q: want a whole number of seconds, minutes or hours, such as 90s, 30m or 1h", s)
	if len(s) < 2 || s[0] == '0' {
		return 0, bad
	}
	unit, ok := units[s[len(s)-1]]
	if !ok {
		return 0, bad
	}
	n, err := strconv.ParseUint(s[:len(s)-1], 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, bad
	}
	// Compared before multiplying, which could overflow.
	if err != nil || n > uint64(limit/unit) {
		return 0, fmt.Errorf("%s is longer than the %s allowed", s, formatDuration(limit))
	}
	return time.Duration(n) * unit, nil
}

// formatDuration writes a whole duration the way parseDuration reads it.
func formatDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
