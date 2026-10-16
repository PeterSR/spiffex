package state

import "strings"

// wellKnownIssuer is a public issuer that gives tokens to anyone (SPEC
// section 5.3), with the claims that name a token's owner.
type wellKnownIssuer struct {
	// issuer matches exactly, unless subtree is set: then it also matches
	// every issuer that continues it with /.
	issuer      string
	subtree     bool
	ownerClaims []string
}

var wellKnownIssuers = []wellKnownIssuer{
	{"https://token.actions.githubusercontent.com", true, []string{"repository_owner_id", "repository_id", "enterprise_id"}},
	{"https://gitlab.com", false, []string{"namespace_id", "project_id"}},
	{"https://accounts.google.com", false, []string{"sub"}},
	{"accounts.google.com", false, []string{"sub"}},
	{"https://oidc.circleci.com/org", true, []string{"oidc.circleci.com~1project-id"}},
	{"https://login.microsoftonline.com", true, []string{"tid", "oid"}},
	{"https://sts.windows.net", true, []string{"tid", "oid"}},
	{"https://app.terraform.io", false, []string{"terraform_organization_id"}},
}

// wellKnownOwnerClaims returns the owner claims of a well-known shared issuer.
func wellKnownOwnerClaims(issuer string) ([]string, bool) {
	for _, w := range wellKnownIssuers {
		if issuer == w.issuer || w.subtree && strings.HasPrefix(issuer, w.issuer+"/") {
			return w.ownerClaims, true
		}
	}
	return nil, false
}
