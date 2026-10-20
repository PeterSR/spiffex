package state

import (
	"path/filepath"

	"github.com/PeterSR/spiffex/internal/nametemplate"
)

// checkProvider checks what can be known of a provider from its own text,
// before any origin fills in its parameters. It reports whether the
// provider is fit to be expanded.
func (v *validator) checkProvider(path string, p *Provider) bool {
	start := v.count()
	v.checkParams(path, p)
	v.checkRefs(path, p)
	proofs := 0
	for _, set := range []bool{p.Proof.JWT != nil, p.Proof.Keys != nil, p.Proof.Exec != nil} {
		if set {
			proofs++
		}
	}
	if proofs != 1 {
		v.add(field(path, "proof"), "set exactly one of jwt, keys and exec")
		return false
	}
	kind := p.kind()
	if _, isRef := paramRef(p.Name); !isRef {
		if _, err := ParseTemplate(p.Name, kind); err != nil {
			v.add(field(path, "name"), "%v", err)
		}
	}
	if p.X509.cn() != nil {
		if _, err := nametemplate.ParseCN(*p.X509.cn()); err != nil {
			v.add(field(field(path, "x509"), "cn"), "%v", err)
		}
	}
	for i, r := range p.Require {
		if err := checkClaimPath(r); err != nil {
			v.add(index(field(path, "require"), i), "%v", err)
		}
	}
	for _, entries := range []struct {
		name  string
		conds map[string]Strings
	}{{"match", p.Match}, {"deny", p.Deny}} {
		for _, claim := range sortedKeys(entries.conds) {
			at := field(field(path, entries.name), claim)
			if err := checkClaimPath(claim); err != nil {
				v.add(at, "%v", err)
			}
			patterns := entries.conds[claim]
			for i, pattern := range patterns.Values {
				if err := checkPattern(pattern); err != nil {
					if patterns.List {
						v.add(index(at, i), "%v", err)
					} else {
						v.add(at, "%v", err)
					}
				}
			}
		}
	}
	if kind == KindKeys && (len(p.Require) > 0 || len(p.Match) > 0 || len(p.Deny) > 0) {
		v.add(path, "a keys proof takes no require, match or deny")
	}
	if a := p.Audiences; a != nil {
		for i, pattern := range a.Values {
			if _, isRef := paramRef(pattern); isRef {
				continue
			}
			if err := checkPattern(pattern); err != nil {
				at := field(path, "audiences")
				if a.List {
					at = index(at, i)
				}
				v.add(at, "%v", err)
			}
		}
	}
	switch kind {
	case KindJWT:
		v.checkJWTProof(field(field(path, "proof"), "jwt"), p.Proof.JWT)
	case KindExec:
		v.checkExecProof(field(field(path, "proof"), "exec"), p.Proof.Exec)
	}
	return v.count() == start
}

func (v *validator) checkJWTProof(path string, j *JWTProof) {
	sources := 0
	for _, set := range []bool{j.JWKS != nil, j.JWKSURI != "", j.JWKSFile != "", j.Discovery} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		v.add(path, "set exactly one of jwks, jwks_uri, jwks_file and discovery: true")
	}
	if j.JWKS != nil {
		if _, err := parseJWKS(j.JWKS); err != nil {
			v.add(field(path, "jwks"), "%v", err)
		}
	}
	if _, isRef := paramRef(j.JWKSURI); j.JWKSURI != "" && !isRef {
		if err := checkHTTPSURL(j.JWKSURI); err != nil {
			v.add(field(path, "jwks_uri"), "%v", err)
		}
	}
	if _, isRef := paramRef(j.Issuer); j.Discovery && !isRef {
		if err := checkHTTPSURL(j.Issuer); err != nil {
			v.add(field(path, "issuer"), "discovery needs an https issuer: %v", err)
		}
	}
	if (j.JWKS != nil || j.JWKSFile != "") && (j.CAFile != "" || j.BearerTokenFile != "") {
		v.add(path, "ca_file and bearer_token_file only apply to keys fetched over the network")
	}
	if oc := j.OwnerClaims; oc != nil && oc.List {
		for i, claim := range oc.Values {
			if _, isRef := paramRef(claim); isRef {
				continue
			}
			if err := checkOwnerClaim(claim); err != nil {
				v.add(index(field(path, "owner_claims"), i), "%v", err)
			}
		}
	}
	if _, isRef := paramRef(j.MaxTokenLifetime); j.MaxTokenLifetime != "" && !isRef {
		if _, err := parseDuration(j.MaxTokenLifetime, maxMaxTokenLifetime); err != nil {
			v.add(field(path, "max_token_lifetime"), "%v", err)
		}
	}
}

func (v *validator) checkExecProof(path string, e *ExecProof) {
	if len(e.Command) == 0 {
		v.add(field(path, "command"), "name the verifier to run")
	} else if cmd := e.Command[0]; !filepath.IsAbs(cmd) || filepath.Clean(cmd) != cmd {
		v.add(index(field(path, "command"), 0), "%q must be a clean absolute path", cmd)
	}
	if e.Timeout != "" {
		if _, err := parseDuration(e.Timeout, maxExecTimeout); err != nil {
			v.add(field(path, "timeout"), "%v", err)
		}
	}
	for i, claim := range e.OwnerClaims {
		if err := checkOwnerClaim(claim); err != nil {
			v.add(index(field(path, "owner_claims"), i), "%v", err)
		}
	}
}
