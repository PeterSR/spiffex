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
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// OAuth 2.0 identifiers used on the token endpoint.
const (
	GrantClientCredentials = "client_credentials"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	ClientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
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
)

// assertionAlgorithms are the algorithms accepted on client assertions.
var assertionAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}

// Client is a workload registered for private_key_jwt authentication.
type Client struct {
	ID         string
	SPIFFEID   spiffeid.ID
	PublicKeys []crypto.PublicKey
	// Audiences, when non-empty, is the only audiences the client may request.
	Audiences []string
}

// ClientSource looks up registered clients. It is consulted on every request,
// so an implementation can swap registrations at runtime.
type ClientSource interface {
	Client(id string) (Client, bool)
}

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

var errInvalidTarget = &oauthError{http.StatusBadRequest, "invalid_target", "audience not permitted"}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	SPIFFEID        string `json:"spiffe_id"`
}

func (iss *Issuer) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	id, audiences, err := iss.authorizeTokenRequest(r)
	if err != nil {
		var oe *oauthError
		if !errors.As(err, &oe) {
			iss.cfg.Logger.Error("token request failed", "error", err)
			oe = &oauthError{http.StatusInternalServerError, "server_error", ""}
		}
		writeJSON(w, oe.status, oe, "no-store")
		return
	}
	token, expires, err := iss.Mint(id, audiences)
	if err != nil {
		iss.cfg.Logger.Error("minting a JWT-SVID failed", "spiffe_id", id, "error", err)
		writeJSON(w, http.StatusInternalServerError, &oauthError{Code: "server_error"}, "no-store")
		return
	}
	iss.cfg.Logger.Info("issued JWT-SVID", "spiffe_id", id, "audience", audiences)
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:     token,
		IssuedTokenType: TokenTypeJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(math.Ceil(expires.Sub(iss.cfg.Now()).Seconds())),
		SPIFFEID:        id.String(),
	}, "no-store")
}

// authorizeTokenRequest authenticates the caller and returns the identity and
// audiences to mint for.
func (iss *Issuer) authorizeTokenRequest(r *http.Request) (spiffeid.ID, []string, error) {
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/x-www-form-urlencoded" {
		return spiffeid.ID{}, nil, errInvalidRequest("content type must be application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		return spiffeid.ID{}, nil, errInvalidRequest("malformed request body")
	}
	form := r.PostForm
	if err := singleValued(form); err != nil {
		return spiffeid.ID{}, nil, err
	}
	if form.Has("actor_token") {
		return spiffeid.ID{}, nil, errInvalidRequest("actor_token is not supported")
	}
	if len(form["audience"]) == 0 {
		return spiffeid.ID{}, nil, errInvalidRequest("audience is required")
	}

	switch grant := form.Get("grant_type"); grant {
	case GrantClientCredentials:
		if iss.cfg.Clients == nil {
			return spiffeid.ID{}, nil, &oauthError{http.StatusBadRequest, "unsupported_grant_type", ""}
		}
		client, err := iss.authenticateClient(form)
		if err != nil {
			return spiffeid.ID{}, nil, err
		}
		audiences, err := iss.checkAudiences(form["audience"])
		if err != nil {
			return spiffeid.ID{}, nil, err
		}
		if err := checkAudienceAllowed(audiences, client.Audiences); err != nil {
			return spiffeid.ID{}, nil, err
		}
		return client.SPIFFEID, audiences, nil
	case "":
		return spiffeid.ID{}, nil, errInvalidRequest("grant_type is required")
	default:
		return spiffeid.ID{}, nil, &oauthError{http.StatusBadRequest, "unsupported_grant_type", ""}
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

func checkAudienceAllowed(requested, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, aud := range requested {
		if !slices.Contains(allowed, aud) {
			return errInvalidTarget
		}
	}
	return nil
}

// authenticateClient verifies a private_key_jwt client assertion (RFC 7523).
func (iss *Issuer) authenticateClient(form url.Values) (Client, error) {
	if form.Get("client_assertion_type") != ClientAssertionJWT {
		return Client{}, errInvalidRequest("client_assertion_type must be %s", ClientAssertionJWT)
	}
	raw := form.Get("client_assertion")
	if raw == "" {
		return Client{}, errInvalidRequest("client_assertion is required")
	}
	assertion, err := jwt.ParseSigned(raw, assertionAlgorithms)
	if err != nil || len(assertion.Headers) != 1 {
		return Client{}, errClientAuth
	}

	clientID := form.Get("client_id")
	if clientID == "" {
		// RFC 7523 lets the client omit client_id; the assertion's issuer then
		// names it. It is only a lookup key until the signature is checked.
		var unverified jwt.Claims
		if err := assertion.UnsafeClaimsWithoutVerification(&unverified); err != nil {
			return Client{}, errClientAuth
		}
		clientID = unverified.Issuer
	}
	client, ok := iss.cfg.Clients.Client(clientID)
	keys := client.PublicKeys
	if !ok {
		// Spend the same effort as for a known client, so response times do
		// not reveal which client ids exist.
		keys = []crypto.PublicKey{decoyKeys()[assertion.Headers[0].Algorithm]}
	}
	var claims jwt.Claims
	if !verifyWithAny(assertion, keys, &claims) || !ok {
		iss.cfg.Logger.Debug("client authentication failed", "unverified_client_id", clientID)
		return Client{}, errClientAuth
	}
	now := iss.cfg.Now()
	if err := iss.checkAssertionClaims(claims, clientID, now); err != nil {
		iss.cfg.Logger.Info("rejected client assertion", "client_id", clientID, "reason", err)
		return Client{}, errClientAuth
	}
	if !iss.replay.use(clientID, claims.ID, claims.Expiry.Time().Add(clockSkew), now) {
		iss.cfg.Logger.Warn("rejected a replayed client assertion", "client_id", clientID)
		return Client{}, errClientAuth
	}
	return client, nil
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
