package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/PeterSR/spiffex/internal/ca"
	"github.com/PeterSR/spiffex/internal/exchange"
	"github.com/PeterSR/spiffex/internal/policy"
	"github.com/PeterSR/spiffex/internal/state"
	"github.com/PeterSR/spiffex/internal/verifier"
)

// OAuth 2.0 identifiers used on the token endpoint.
const (
	GrantClientCredentials = "client_credentials"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	ClientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	// TokenTypeExec marks a proof for an exec origin, named by the origin
	// parameter (SPEC section 3.3).
	TokenTypeExec = "urn:spiffex:token-type:exec"
)

const (
	// MaxAudiences is the most distinct audiences one token request may carry.
	MaxAudiences = 5
	// maxAudienceLength bounds a single audience value, in bytes.
	maxAudienceLength = 512
	// maxAssertionLifetime bounds how far in the future a client assertion's
	// exp may be.
	maxAssertionLifetime = 5 * time.Minute
	// clockSkew is tolerated on every time comparison against a client's clock.
	clockSkew = 30 * time.Second
	// maxRequestBody bounds the token endpoint's form body.
	maxRequestBody = 64 << 10
	// maxSubjectToken bounds a subject token (SPEC section 3.3).
	maxSubjectToken = 16 << 10
	// maxManagementTokenTTL is the longest a token for the management
	// endpoint may live (SPEC section 7.1).
	maxManagementTokenTTL = 5 * time.Minute
)

// assertionAlgorithms are the algorithms accepted on client assertions.
var assertionAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}

// ValidateAudience reports whether s is acceptable as one audience value.
func ValidateAudience(s string) error {
	switch {
	case s == "":
		return errors.New("audience must not be empty")
	case len(s) > maxAudienceLength:
		return fmt.Errorf("audience is longer than %d bytes", maxAudienceLength)
	case strings.ContainsFunc(s, unicode.IsControl):
		return errors.New("audience must not contain control characters")
	}
	return nil
}

// oauthError is an RFC 6749 section 5.2 error response.
type oauthError struct {
	status      int
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Description }

func errInvalidRequest(format string, args ...any) *oauthError {
	return &oauthError{http.StatusBadRequest, "invalid_request", fmt.Sprintf(format, args...)}
}

// errClientAuth is the one answer to every failed client authentication, so
// the response does not tell an unknown client from a bad signature.
var errClientAuth = &oauthError{http.StatusUnauthorized, "invalid_client", "client authentication failed"}

// errSubjectToken is the one answer to every refused subject token, so the
// response does not tell a token no origin takes from one its origin
// refuses.
var errSubjectToken = errInvalidRequest("subject token rejected")

var errInvalidTarget = &oauthError{http.StatusBadRequest, "invalid_target", "audience not permitted"}
var errSVIDTypeNotPermitted = &oauthError{http.StatusBadRequest, "invalid_target", "the origin does not issue this kind of SVID"}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	SPIFFEID        string `json:"spiffe_id"`
}

// grant is what an authenticated token request gets: an identity, from an
// origin, for audiences.
type grant struct {
	id        spiffeid.ID
	origin    *policy.Origin
	audiences []string
	// x509Key is the CSR's public key when an X.509-SVID was requested.
	x509Key crypto.PublicKey
	// commonName is the common name of the X.509-SVID, empty for none.
	commonName string
	// ca is the certificate authority this request was judged against.
	ca *ca.Set
}

func (iss *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	g, err := iss.authorizeTokenRequest(r)
	if err != nil {
		var oe *oauthError
		if !errors.As(err, &oe) {
			if iss.errorLog.allow(iss.cfg.Now()) {
				iss.cfg.Logger.Error("token request failed", "error", err)
			}
			oe = &oauthError{http.StatusInternalServerError, "server_error", ""}
		}
		writeJSON(w, oe.status, oe, "no-store")
		return
	}
	if g.x509Key != nil {
		iss.issueX509(w, g)
		return
	}
	token, expires, err := iss.Mint(g.id, g.audiences)
	if errors.Is(err, errNoJWTKeys) {
		// A reload during authentication took the last key: the same state
		// gets the same answer whichever read sees it.
		iss.cfg.Logger.Error("no JWT-SVID can be issued: the issuer has no signing key", "spiffe_id", g.id, "origin", g.origin.Name)
		writeJSON(w, errNoJWTKeys.status, errNoJWTKeys, "no-store")
		return
	}
	if err != nil {
		iss.cfg.Logger.Error("minting a JWT-SVID failed", "spiffe_id", g.id, "error", err)
		writeJSON(w, http.StatusInternalServerError, &oauthError{Code: "server_error"}, "no-store")
		return
	}
	iss.cfg.Logger.Info("issued JWT-SVID", "spiffe_id", g.id, "origin", g.origin.Name, "audience", g.audiences)
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:     token,
		IssuedTokenType: TokenTypeJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(math.Ceil(expires.Sub(iss.cfg.Now()).Seconds())),
		SPIFFEID:        g.id.String(),
	}, "no-store")
}

// authorizeTokenRequest authenticates the caller, then checks the kind of
// SVID and the audiences or the CSR it asks for. All are checked only after
// authentication, so that a refusal tells nothing to someone who could not
// authenticate (SPEC section 3.1).
func (iss *Issuer) authorizeTokenRequest(r *http.Request) (*grant, error) {
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/x-www-form-urlencoded" {
		return nil, errInvalidRequest("content type must be application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		return nil, errInvalidRequest("malformed request body")
	}
	form := r.PostForm
	if err := singleValued(form); err != nil {
		return nil, err
	}
	if form.Has("actor_token") {
		return nil, errInvalidRequest("actor_token is not supported")
	}
	// This read only decides whether the request makes sense at all; the set
	// that signs is read again once the caller is authenticated, which can
	// take a while for a token exchange.
	x509Requested, err := iss.checkRequestedType(form, iss.caSnapshot())
	if err != nil {
		return nil, err
	}

	// One view for the whole request, so a reload halfway cannot mix two
	// versions of the state.
	view := iss.cfg.Policy.Current()
	var g *grant
	switch grantType := form.Get("grant_type"); grantType {
	case GrantClientCredentials:
		g, err = iss.authenticateClient(view, form)
	case GrantTokenExchange:
		g, err = iss.exchange(r, view, form)
	case "":
		return nil, errInvalidRequest("grant_type is required")
	default:
		return nil, &oauthError{http.StatusBadRequest, "unsupported_grant_type", ""}
	}
	if err != nil {
		return nil, err
	}
	if x509Requested {
		if !g.origin.AllowsSVIDType("x509") {
			return nil, errSVIDTypeNotPermitted
		}
		g.ca = iss.caSnapshot()
		if !hasCA(g.ca) {
			// A reload during authentication took the last CA: the same
			// state gets the same answer whichever read sees it.
			return nil, errInvalidRequest("this issuer issues no X.509-SVIDs")
		}
		g.x509Key, err = iss.checkCSR(view, g.ca, form.Get("csr"))
		if err != nil {
			iss.logRejection("rejected a csr", "origin", g.origin.Name, "reason", err)
			return nil, err
		}
		g.commonName, err = g.origin.CommonName(g.id.String(), g.id.Path())
		if err != nil {
			// The origin's template cannot name this identity. The caller is
			// authenticated, so this may say why.
			if iss.warnLog.allow(iss.cfg.Now()) {
				iss.cfg.Logger.Warn("an origin's x509.cn cannot name an identity; no X.509-SVID issued", "origin", g.origin.Name, "spiffe_id", g.id, "error", err)
			}
			return nil, errInvalidRequest("the origin cannot name this identity in the subject of an X.509-SVID")
		}
		return g, nil
	}
	if g.audiences, err = iss.checkAudiences(form["audience"]); err != nil {
		return nil, err
	}
	if !g.origin.AllowsSVIDType("jwt") {
		return nil, errSVIDTypeNotPermitted
	}
	for _, aud := range g.audiences {
		if !g.origin.AllowsAudience(aud) {
			return nil, errInvalidTarget
		}
	}
	return g, nil
}

// checkRequestedType reads requested_token_type and checks the parameters
// that go with it, which are properties of the request alone (SPEC section
// 3.4). It reports whether an X.509-SVID was requested.
func (iss *Issuer) checkRequestedType(form url.Values, caSet *ca.Set) (bool, error) {
	switch rt := form.Get("requested_token_type"); rt {
	case "", TokenTypeJWT:
		if form.Has("csr") {
			return false, errInvalidRequest("csr goes only with requested_token_type %s", TokenTypeX509SVID)
		}
		if len(form["audience"]) == 0 {
			return false, errInvalidRequest("audience is required")
		}
		if !iss.hasJWTKeys() {
			return false, errNoJWTKeys
		}
		return false, nil
	case TokenTypeX509SVID:
		switch {
		case form.Has("audience"):
			return false, errInvalidRequest("audience is not allowed with requested_token_type %s", TokenTypeX509SVID)
		case form.Get("csr") == "":
			return false, errInvalidRequest("csr is required with requested_token_type %s", TokenTypeX509SVID)
		case !hasCA(caSet):
			return false, errInvalidRequest("this issuer issues no X.509-SVIDs")
		}
		return true, nil
	default:
		return false, errInvalidRequest("requested_token_type must be %s or %s", TokenTypeJWT, TokenTypeX509SVID)
	}
}

// exchange verifies an RFC 8693 subject token (SPEC section 3.3).
func (iss *Issuer) exchange(r *http.Request, view *policy.View, form url.Values) (*grant, error) {
	token := form.Get("subject_token")
	if token == "" {
		return nil, errInvalidRequest("subject_token is required")
	}
	if len(token) > maxSubjectToken {
		return nil, errInvalidRequest("subject_token is larger than %d bytes", maxSubjectToken)
	}
	var g *grant
	var err error
	switch tokenType := form.Get("subject_token_type"); tokenType {
	case TokenTypeJWT, TokenTypeIDToken:
		if form.Has("origin") {
			return nil, errInvalidRequest("origin goes only with subject_token_type %s", TokenTypeExec)
		}
		g, err = iss.exchangeJWT(r, view, token)
	case TokenTypeExec:
		name := form.Get("origin")
		if name == "" {
			return nil, errInvalidRequest("origin is required with subject_token_type %s", TokenTypeExec)
		}
		g, err = iss.exchangeExec(r, view, name, token)
	default:
		return nil, errInvalidRequest("subject_token_type must be %s, %s or %s", TokenTypeJWT, TokenTypeIDToken, TokenTypeExec)
	}
	// The reasons go to the log; the caller learns only that it failed.
	var refused *state.RefusedError
	switch {
	case errors.As(err, &refused):
		iss.logRejection("the origin does not admit the subject token", "origin", g.origin.Name, "reason", refused.LogDetail())
		return nil, errSubjectToken
	case errors.Is(err, exchange.ErrRejected), errors.Is(err, verifier.ErrRejected):
		attrs := []any{"reason", err}
		if g != nil {
			attrs = append(attrs, "origin", g.origin.Name)
		}
		iss.logRejection("subject token rejected", attrs...)
		return nil, errSubjectToken
	case err != nil:
		return nil, err
	}
	return g, nil
}

// exchangeJWT verifies a JWT from an upstream against the one origin it
// reaches, and asks that origin for an identity. A rejection comes back
// with the grant when an origin was reached, for the log.
func (iss *Issuer) exchangeJWT(r *http.Request, view *policy.View, raw string) (*grant, error) {
	token, err := exchange.Parse(raw)
	if err != nil {
		return nil, err
	}
	if token.Issuer == iss.cfg.URL {
		return nil, fmt.Errorf("%w: the token comes from this issuer", exchange.ErrRejected)
	}
	reached := view.Reached(token.Issuer, token.Audience)
	switch len(reached) {
	case 0:
		return nil, fmt.Errorf("%w: no origin takes tokens from %q with audiences %q", exchange.ErrRejected, token.Issuer, token.Audience)
	case 1:
	default:
		return nil, fmt.Errorf("%w: the audiences %q name %d origins", exchange.ErrRejected, token.Audience, len(reached))
	}
	g := &grant{origin: reached[0]}
	claims, err := token.Verify(r.Context(), g.origin.JWT, g.origin.Keys, iss.cfg.Now())
	if errors.Is(err, exchange.ErrRejected) {
		return g, err
	}
	if err != nil {
		return nil, fmt.Errorf("origin %s: %w", g.origin.Name, err)
	}
	g.id, err = g.origin.Admit(iss.cfg.TrustDomain, claims)
	return g, err
}

// exchangeExec has the named exec origin's verifier check the proof, and
// asks the origin for an identity from the claims it made.
func (iss *Issuer) exchangeExec(r *http.Request, view *policy.View, name, proof string) (*grant, error) {
	origin, ok := view.Exec(name)
	if !ok {
		return nil, fmt.Errorf("%w: no exec origin is named %q", verifier.ErrRejected, name)
	}
	g := &grant{origin: origin}
	claims, err := iss.cfg.Verifiers.Run(r.Context(), verifier.Request{
		Issuer:       iss.cfg.URL,
		Origin:       origin.Expanded,
		SubjectToken: proof,
		Client:       iss.clientAddress(r),
	})
	if errors.Is(err, verifier.ErrRejected) {
		return g, err
	}
	if err != nil {
		return nil, fmt.Errorf("origin %s: %w", name, err)
	}
	g.id, err = origin.Admit(iss.cfg.TrustDomain, claims)
	return g, err
}

// clientAddress is the address a request came from. When the peer is a
// trusted proxy, it is the rightmost address in X-Forwarded-For that is not
// itself a trusted proxy: addresses further left were written by whoever
// sent the request, and could be anything.
func (iss *Issuer) clientAddress(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := ap.Addr().Unmap()
	if !iss.trustedProxy(addr) {
		return addr
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addr
		}
		addr = hop.Unmap()
		if !iss.trustedProxy(addr) {
			return addr
		}
	}
	return addr
}

func (iss *Issuer) trustedProxy(addr netip.Addr) bool {
	for _, p := range iss.cfg.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// logRejection logs why a request was refused. Anyone can send requests,
// so the lines are rate limited.
func (iss *Issuer) logRejection(msg string, attrs ...any) {
	if iss.rejectLog.allow(iss.cfg.Now()) {
		iss.cfg.Logger.Info(msg, attrs...)
	}
}

// singleValued rejects any repeated parameter except the two that may repeat.
func singleValued(form url.Values) error {
	for name, values := range form {
		if len(values) > 1 && name != "audience" && name != "resource" {
			return errInvalidRequest("%s must not repeat", name)
		}
	}
	return nil
}

// authenticateClient verifies a private_key_jwt client assertion (SPEC
// section 3.2).
func (iss *Issuer) authenticateClient(view *policy.View, form url.Values) (*grant, error) {
	if form.Get("client_assertion_type") != ClientAssertionJWT {
		return nil, errInvalidRequest("client_assertion_type must be %s", ClientAssertionJWT)
	}
	raw := form.Get("client_assertion")
	if raw == "" {
		return nil, errInvalidRequest("client_assertion is required")
	}
	assertion, err := jwt.ParseSigned(raw, assertionAlgorithms)
	if err != nil || len(assertion.Headers) != 1 {
		return nil, errClientAuth
	}

	clientID := form.Get("client_id")
	if clientID == "" {
		// The client may omit client_id; the assertion's issuer then names
		// it. It is only a lookup key until the signature is checked.
		var unverified jwt.Claims
		if err := assertion.UnsafeClaimsWithoutVerification(&unverified); err != nil {
			return nil, errClientAuth
		}
		clientID = unverified.Issuer
	}
	origin, member, keys, ok := view.Member(clientID)
	alg := assertion.Headers[0].Algorithm
	keys = keysFor(alg, keys)
	if !ok || len(keys) == 0 {
		// Spend the same effort as for a client with a key of this type, so
		// response times reveal neither which client ids exist nor which
		// types of key they have.
		keys, ok = []crypto.PublicKey{decoyKeys()[alg]}, false
	}
	var claims jwt.Claims
	if !verifyWithAny(assertion, keys, &claims) || !ok {
		iss.cfg.Logger.Debug("client authentication failed", "unverified_client_id", clientID)
		return nil, errClientAuth
	}
	now := iss.cfg.Now()
	if err := iss.checkAssertionClaims(claims, clientID, now); err != nil {
		iss.logRejection("rejected client assertion", "client_id", clientID, "reason", err)
		return nil, errClientAuth
	}
	if !iss.replay.use(clientID, claims.ID, claims.Expiry.Time().Add(clockSkew), now) {
		iss.cfg.Logger.Warn("rejected a replayed client assertion", "client_id", clientID)
		return nil, errClientAuth
	}
	id, err := origin.MemberID(iss.cfg.TrustDomain, member)
	if err != nil {
		return nil, fmt.Errorf("naming member %s: %w", clientID, err)
	}
	return &grant{id: id, origin: origin}, nil
}

// decoyKeys has one key per accepted algorithm, so verifying an unknown
// client's assertion costs what verifying a known client's would.
var decoyKeys = sync.OnceValue(func() map[string]crypto.PublicKey {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return map[string]crypto.PublicKey{string(jose.ES256): &ec.PublicKey, string(jose.RS256): &rsaKey.PublicKey}
})

// keysFor returns the keys that can verify a signature made with alg.
func keysFor(alg string, keys []crypto.PublicKey) []crypto.PublicKey {
	var out []crypto.PublicKey
	for _, k := range keys {
		switch k.(type) {
		case *ecdsa.PublicKey:
			if alg == string(jose.ES256) {
				out = append(out, k)
			}
		case *rsa.PublicKey:
			if alg == string(jose.RS256) {
				out = append(out, k)
			}
		}
	}
	return out
}

func verifyWithAny(assertion *jwt.JSONWebToken, keys []crypto.PublicKey, claims *jwt.Claims) bool {
	for _, key := range keys {
		if assertion.Claims(key, claims) == nil {
			return true
		}
	}
	return false
}

func (iss *Issuer) checkAssertionClaims(c jwt.Claims, clientID string, now time.Time) error {
	if c.Issuer != clientID || c.Subject != clientID {
		return errors.New("iss and sub must both equal client_id")
	}
	if len(c.Audience) != 1 || c.Audience[0] != iss.cfg.URL {
		return errors.New("aud must be the issuer URL and nothing else")
	}
	if c.Expiry == nil {
		return errors.New("exp is required")
	}
	if c.ID == "" {
		return errors.New("jti is required")
	}
	exp := c.Expiry.Time()
	if !now.Before(exp.Add(clockSkew)) {
		return errors.New("expired")
	}
	if c.NotBefore != nil && now.Add(clockSkew).Before(c.NotBefore.Time()) {
		return errors.New("not valid yet")
	}
	if c.IssuedAt != nil && now.Add(clockSkew).Before(c.IssuedAt.Time()) {
		return errors.New("issued in the future")
	}
	if exp.After(now.Add(maxAssertionLifetime + clockSkew)) {
		return fmt.Errorf("expires more than %s from now", maxAssertionLifetime)
	}
	return nil
}
