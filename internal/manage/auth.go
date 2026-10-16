package manage

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// maxTokenLifetime is the longest a management token may be meant to live,
// exp minus iat (SPEC section 8.1).
const maxTokenLifetime = 5 * time.Minute

// maxReplayEntries bounds the token IDs remembered from writes. Only
// authorized writes are remembered, so only callers with grants can fill the
// record; when it is full, writes are refused until entries expire, as
// forgetting one would let its token write again.
const maxReplayEntries = 1 << 16

var tokenAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}

// caller is an authenticated management client.
type caller struct {
	id      spiffeid.ID
	tokenID string
	expires time.Time
}

// authenticated checks the bearer token of a request, and that the caller
// is still issuable under the state in service, before passing it on with
// that state; it answers 401 otherwise. Nothing touches storage before
// these checks, and each caller is held to a rate.
func (s *Server) authenticated(h func(http.ResponseWriter, *http.Request, caller, *base)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.authenticate(r)
		if err != nil {
			s.cfg.Logger.Debug("management request not authenticated", "error", err, "path", r.URL.Path)
			writeError(w, errUnauthenticated)
			return
		}
		b := s.inService()
		if !s.issuable(b, c) {
			s.cfg.Logger.Debug("management request from an identity no origin issues any more", "caller", c.id)
			writeError(w, errUnauthenticated)
			return
		}
		if !s.limiter.allow(c.id.String(), s.cfg.Now()) {
			w.Header().Set("Retry-After", "1")
			writeError(w, errorf(http.StatusTooManyRequests, "too many requests; slow down"))
			return
		}
		h(w, r, c, b)
	}
}

var errUnauthenticated = &apiError{status: http.StatusUnauthorized, msg: "a valid management token is required"}

func (s *Server) authenticate(r *http.Request) (caller, error) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return caller{}, errors.New("no bearer token")
	}
	token, err := jwt.ParseSigned(raw, tokenAlgorithms)
	if err != nil {
		return caller{}, err
	}
	if len(token.Headers) != 1 {
		return caller{}, errors.New("want exactly one signature")
	}
	header := token.Headers[0]
	set, _, _ := s.cfg.Keys.Current()
	var claims jwt.Claims
	verified := false
	for _, k := range set.Keys() {
		if k.ID == header.KeyID && string(k.Algorithm) == header.Algorithm {
			verified = token.Claims(k.Signer.Public(), &claims) == nil
			break
		}
	}
	if !verified {
		return caller{}, errors.New("the token is not signed with a published key")
	}
	return s.checkClaims(claims)
}

func (s *Server) checkClaims(c jwt.Claims) (caller, error) {
	now := s.cfg.Now()
	switch {
	case c.Issuer != s.cfg.Settings.Issuer:
		return caller{}, fmt.Errorf("iss %q is not the issuer URL", c.Issuer)
	case len(c.Audience) != 1 || c.Audience[0] != s.audience:
		return caller{}, fmt.Errorf("aud %q is not exactly %s", []string(c.Audience), s.audience)
	case c.Expiry == nil || c.IssuedAt == nil:
		return caller{}, errors.New("exp and iat are required")
	case !now.Before(c.Expiry.Time()):
		return caller{}, errors.New("the token has expired")
	case c.Expiry.Time().Sub(c.IssuedAt.Time()) > maxTokenLifetime:
		return caller{}, fmt.Errorf("the token was issued to live longer than %s", maxTokenLifetime)
	case c.NotBefore != nil && now.Before(c.NotBefore.Time()):
		return caller{}, errors.New("the token is not valid yet")
	case c.ID == "":
		return caller{}, errors.New("jti is required")
	}
	id, err := spiffeid.FromString(c.Subject)
	if err != nil {
		return caller{}, fmt.Errorf("sub: %w", err)
	}
	if !id.MemberOf(s.cfg.Settings.TrustDomain) {
		return caller{}, fmt.Errorf("sub %s is not in trust domain %s", id, s.cfg.Settings.TrustDomain)
	}
	return caller{id: id, tokenID: c.ID, expires: c.Expiry.Time()}, nil
}

// replayCache remembers the IDs of tokens used for authorized writes until
// they expire, so each token writes at most once in this process (SPEC
// section 8.1).
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]time.Time{}}
}

// Why a token cannot write.
var (
	errReplayed   = errors.New("the token was used for a write before")
	errReplayFull = errors.New("too many recent writes are remembered to take another")
)

// use records a token ID, refusing one used before, and any while the
// record is full.
func (c *replayCache) use(id string, expires, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.seen[id]; ok && now.Before(until) {
		return errReplayed
	}
	if len(c.seen) >= maxReplayEntries {
		for jti, until := range c.seen {
			if !now.Before(until) {
				delete(c.seen, jti)
			}
		}
		if len(c.seen) >= maxReplayEntries {
			return errReplayFull
		}
	}
	c.seen[id] = expires
	return nil
}
