package state

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Settings is what validation needs from the issuer's own settings, which
// live outside the state.
type Settings struct {
	// Issuer is the issuer URL.
	Issuer      string
	TrustDomain spiffeid.TrustDomain
	// ReadableFiles may be named as jwks_file or ca_file.
	ReadableFiles []string
	// BearerTokenFiles may be named as bearer_token_file, each only for
	// fetching keys from its hosts.
	BearerTokenFiles []BearerTokenFile
	// Verifiers are the complete argument vectors an exec proof's command
	// may be. A verifier runs inside the issuer's trust boundary, so only
	// the operator can install one; there are none by default.
	Verifiers [][]string
}

// BearerTokenFile is a file holding a bearer token, and the hosts the token
// may be sent to.
type BearerTokenFile struct {
	Path string
	// Hosts are compared with the host of the URL keys are fetched from,
	// port included, ignoring case.
	Hosts []string
}

// The in-cluster service account files that the shipped kubernetes provider
// needs, and the API server host its token may go to.
const (
	ServiceAccountCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	ServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	InClusterAPIHost        = "kubernetes.default.svc.cluster.local"
)

// DefaultSettings allows exactly the files the shipped kubernetes provider
// needs, and nothing else (SPEC section 5.2).
func DefaultSettings(issuer string, td spiffeid.TrustDomain) Settings {
	return Settings{
		Issuer:           issuer,
		TrustDomain:      td,
		ReadableFiles:    []string{ServiceAccountCAFile},
		BearerTokenFiles: []BearerTokenFile{{Path: ServiceAccountTokenFile, Hosts: []string{InClusterAPIHost}}},
	}
}

// Check reports whether the settings can be validated against.
func (s Settings) Check() error {
	if s.Issuer == "" {
		return errors.New("the issuer URL is required")
	}
	u, err := url.Parse(s.Issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(s.Issuer, "/") {
		return fmt.Errorf("issuer URL %q must be an https URL (http only for local development) with no query, fragment, user information or trailing slash", s.Issuer)
	}
	if s.TrustDomain.IsZero() {
		return errors.New("the trust domain is required")
	}
	return nil
}

// ManagementEndpoint is the URL of the management API, and the audience of
// management tokens (SPEC section 8.1).
func (s Settings) ManagementEndpoint() string { return s.Issuer + "/manage" }

func (s Settings) readable(path string) bool {
	for _, f := range s.ReadableFiles {
		if f == path {
			return true
		}
	}
	return false
}

// verifier reports whether command is an installed verifier. The comparison
// is of strings only: resolving symbolic links would let the state name a
// path whose target someone else controls.
func (s Settings) verifier(command []string) bool {
	return slices.ContainsFunc(s.Verifiers, func(v []string) bool { return slices.Equal(v, command) })
}

func (s Settings) bearerTokenFile(path string) (BearerTokenFile, bool) {
	for _, f := range s.BearerTokenFiles {
		if f.Path == path {
			return f, true
		}
	}
	return BearerTokenFile{}, false
}
