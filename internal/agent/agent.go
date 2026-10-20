// Package agent implements the spiffex agent: the SPIFFE Workload API, JWT
// and X.509 profiles, served on a Unix socket for one workload, backed by a
// spiffex issuer.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PeterSR/spiffex/internal/state"
)

const (
	// defaultRefreshHint is used when the bundle carries no refresh hint.
	defaultRefreshHint = 5 * time.Minute
	// minRefresh keeps a misconfigured hint from turning into a request storm.
	minRefresh = 5 * time.Second
	// maxTokenCacheEntries bounds the per-audience token cache; a workload
	// asking for more distinct audience sets than this starts over.
	maxTokenCacheEntries = 256
	// maxConcurrentFetches bounds requests to the issuer in flight at once.
	maxConcurrentFetches = 4
	// maxAudiences and maxAudienceLength mirror the issuer's limits.
	maxAudiences      = 5
	maxAudienceLength = 512
)

// Config configures an Agent.
type Config struct {
	Issuer     *IssuerClient
	Credential Credential
	Logger     *slog.Logger
}

// Agent serves the Workload API for one workload.
type Agent struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	issuer *IssuerClient
	cred   Credential
	logger *slog.Logger

	tokenMu  sync.Mutex
	tokens   map[string]Token
	inflight map[string]*tokenCall
	// fetchSlots bounds concurrent requests to the issuer, so a workload
	// asking for many audiences at once cannot turn the agent into an
	// amplifier for its credential.
	fetchSlots chan struct{}
	id         spiffeid.ID // the workload's identity, once known

	// refreshMu serializes bundle refreshes, so a fetch that began earlier
	// can never store its result over a later one's.
	refreshMu sync.Mutex
	bundleMu  sync.RWMutex
	bundle    *spiffebundle.Bundle
	// bundleChanged is closed, and replaced, when the bundle's authorities
	// or the issuer's X.509 support change.
	bundleChanged chan struct{}

	x509 *x509Hub
}

// New returns an Agent. Call Run to start fetching the bundle and Serve to
// accept connections.
func New(cfg Config) (*Agent, error) {
	if cfg.Issuer == nil || cfg.Credential == nil {
		return nil, errors.New("an issuer and a credential are required")
	}
	if err := cfg.Credential.validate(); err != nil {
		return nil, &CredentialError{err}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Agent{
		issuer:        cfg.Issuer,
		cred:          cfg.Credential,
		logger:        cfg.Logger,
		tokens:        make(map[string]Token),
		inflight:      make(map[string]*tokenCall),
		fetchSlots:    make(chan struct{}, maxConcurrentFetches),
		bundleChanged: make(chan struct{}),
	}
	a.x509 = newX509Hub(a)
	return a, nil
}

// Run keeps the trust bundle current until ctx is done: it fetches at once,
// retries with backoff on failure, and otherwise refreshes at the bundle's
// refresh hint.
func (a *Agent) Run(ctx context.Context) {
	backoff := time.Second
	for {
		wait := a.refreshBundle(ctx)
		if wait == 0 {
			wait = backoff
			backoff = min(backoff*2, time.Minute)
		} else {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refreshBundle fetches the bundle and returns how long to wait before the
// next fetch, or zero if the fetch failed.
func (a *Agent) refreshBundle(ctx context.Context) time.Duration {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	bundle, err := a.issuer.FetchBundle(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.logger.Warn("fetching the trust bundle failed", "error", err)
		}
		return 0
	}
	supportChanged, err := a.issuer.refreshX509Support(ctx)
	if err != nil && ctx.Err() == nil {
		a.logger.Warn("rereading the issuer's discovery document failed", "error", err)
	}
	a.bundleMu.Lock()
	if supportChanged || a.bundle == nil || !sameAuthorities(a.bundle, bundle) {
		a.bundle = bundle
		close(a.bundleChanged)
		a.bundleChanged = make(chan struct{})
		a.logger.Info("trust bundle updated", "keys", len(bundle.JWTAuthorities()), "x509_authorities", len(bundle.X509Authorities()), "x509_svids", a.issuer.X509Supported())
	}
	a.bundleMu.Unlock()
	a.dropTokensOfRemovedKeys(bundle)

	hint, ok := bundle.RefreshHint()
	if !ok {
		hint = defaultRefreshHint
	}
	return max(hint, minRefresh)
}

// signedByCurrentKey reports whether the token's key is in the bundle the agent
// holds now. Without a bundle yet there is nothing to judge by.
func (a *Agent) signedByCurrentKey(t Token) bool {
	bundle, _ := a.currentBundle()
	if bundle == nil {
		return true
	}
	_, ok := bundle.JWTAuthorities()[t.KeyID]
	return ok
}

// dropTokensOfRemovedKeys forgets the cached JWT-SVIDs signed by a key that
// has left the bundle: removing a key revokes what it signed, and a workload
// must not be handed a token every verifier now refuses.
func (a *Agent) dropTokensOfRemovedKeys(bundle *spiffebundle.Bundle) {
	authorities := bundle.JWTAuthorities()
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	for key, t := range a.tokens {
		if _, ok := authorities[t.KeyID]; !ok {
			delete(a.tokens, key)
		}
	}
}

// sameAuthorities compares only the keys and certificates. Sequence numbers
// and refresh hints differ between issuer processes and are no reason to
// notify workloads.
func sameAuthorities(a, b *spiffebundle.Bundle) bool {
	return jwtbundle.FromJWTAuthorities(a.TrustDomain(), a.JWTAuthorities()).
		Equal(jwtbundle.FromJWTAuthorities(b.TrustDomain(), b.JWTAuthorities())) &&
		sameX509Authorities(a, b)
}

func sameX509Authorities(a, b *spiffebundle.Bundle) bool {
	return x509bundle.FromX509Authorities(a.TrustDomain(), a.X509Authorities()).
		Equal(x509bundle.FromX509Authorities(b.TrustDomain(), b.X509Authorities()))
}

func (a *Agent) currentBundle() (*spiffebundle.Bundle, <-chan struct{}) {
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return a.bundle, a.bundleChanged
}

// Listen creates the Unix socket at path with the given permissions,
// replacing a stale socket but nothing else. The socket is created in a
// private directory and moved into place, so it never exists at path with
// looser permissions.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	// sockaddr_un holds 104 (BSD) to 108 (Linux) bytes including the NUL.
	if len(path) > 103 {
		return nil, fmt.Errorf("socket path %s is %d bytes, longer than Unix sockets allow (103)", path, len(path))
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	private, err := os.MkdirTemp(filepath.Dir(path), ".sx")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(private)
	staging := filepath.Join(private, "s")
	if len(staging) > 103 {
		return nil, fmt.Errorf("socket directory %s is too deep for a Unix socket; use a shorter path", filepath.Dir(path))
	}
	l, err := net.Listen("unix", staging)
	if err != nil {
		return nil, err
	}
	ul := l.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(staging, mode); err != nil {
		l.Close()
		return nil, err
	}
	if err := os.Rename(staging, path); err != nil {
		l.Close()
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		l.Close()
		return nil, err
	}
	return &unlinkingListener{UnixListener: ul, path: path, info: info}, nil
}

// unlinkingListener removes its socket file on Close, unless something else
// has taken its place meanwhile.
type unlinkingListener struct {
	*net.UnixListener
	path string
	info os.FileInfo
}

func (l *unlinkingListener) Close() error {
	err := l.UnixListener.Close()
	if now, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(now, l.info) {
		_ = os.Remove(l.path)
	}
	return err
}

// NewServer returns a gRPC server with the agent registered and the Workload
// API's security header enforced.
func (a *Agent) NewServer() *grpc.Server {
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := checkSecurityHeader(ctx); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := checkSecurityHeader(ss.Context()); err != nil {
				return err
			}
			return handler(srv, ss)
		}),
	)
	workload.RegisterSpiffeWorkloadAPIServer(srv, a)
	return srv
}

func checkSecurityHeader(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if !slices.Contains(md.Get("workload.spiffe.io"), "true") {
		return status.Error(codes.InvalidArgument, "security header missing from request")
	}
	return nil
}

// FetchJWTSVID returns a JWT-SVID for the requested audiences.
func (a *Agent) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	audiences, err := a.checkAudiences(req.Audience)
	if err != nil {
		return nil, err
	}
	var want spiffeid.ID
	if req.SpiffeId != "" {
		if want, err = spiffeid.FromString(req.SpiffeId); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "spiffe_id: %v", err)
		}
		if known := a.identity(); !known.IsZero() && known != want {
			return nil, status.Errorf(codes.PermissionDenied, "this agent serves %s", known)
		}
	}
	token, err := a.token(ctx, audiences)
	if err != nil {
		return nil, err
	}
	if !want.IsZero() && want != token.SPIFFEID {
		return nil, status.Errorf(codes.PermissionDenied, "this agent serves %s", token.SPIFFEID)
	}
	return &workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{{SpiffeId: token.SPIFFEID.String(), Svid: token.Value}},
	}, nil
}

// checkAudiences applies the issuer's audience rules (SPEC section 3) before
// any request is made, and returns the audiences sorted and deduplicated.
func (a *Agent) checkAudiences(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}
	audiences := slices.Clone(requested)
	slices.Sort(audiences)
	audiences = slices.Compact(audiences)
	if len(audiences) > maxAudiences {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d audiences may be requested", maxAudiences)
	}
	for _, aud := range audiences {
		switch {
		case aud == "" || len(aud) > maxAudienceLength || strings.ContainsFunc(aud, unicode.IsControl):
			return nil, status.Errorf(codes.InvalidArgument, "audience %q is not acceptable", truncate(aud, 64))
		case a.issuer.selfAudience(aud):
			return nil, status.Error(codes.InvalidArgument, "the issuer itself cannot be an audience")
		}
	}
	return audiences, nil
}

func (a *Agent) identity() spiffeid.ID {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	return a.id
}

// tokenCall is one token request in flight, shared by every caller that
// wants the same audiences meanwhile.
type tokenCall struct {
	done  chan struct{}
	token Token
	err   error
}

// token returns a cached token for the audiences while it has more than half
// its lifetime left, and fetches a new one otherwise. Concurrent callers
// asking for the same audiences share one request, and each waits only as
// long as its own context allows. Tokens for the management endpoint are
// the exception: each caller gets a fresh one.
func (a *Agent) token(ctx context.Context, audiences []string) (Token, error) {
	if len(audiences) == 1 && audiences[0] == state.ManagementAudience(a.issuer.URL()) {
		return a.singleUseToken(ctx, audiences)
	}
	key := strings.Join(audiences, "\x00")
	call, err := a.joinOrStart(ctx, key, audiences, false)
	if err != nil {
		return Token{}, err
	}
	if call.done == nil {
		return call.token, nil
	}
	select {
	case <-ctx.Done():
		return Token{}, status.FromContextError(ctx.Err()).Err()
	case <-call.done:
		return call.token, call.err
	}
}

// joinOrStart returns a fresh cached token (as a call with no done channel),
// joins a request in flight for key, or starts one once a fetch slot is free.
func (a *Agent) joinOrStart(ctx context.Context, key string, audiences []string, haveSlot bool) (*tokenCall, error) {
	a.tokenMu.Lock()
	if t, fresh := a.freshToken(key); fresh {
		a.tokenMu.Unlock()
		if haveSlot {
			<-a.fetchSlots
		}
		return &tokenCall{token: t}, nil
	}
	if call := a.inflight[key]; call != nil {
		a.tokenMu.Unlock()
		if haveSlot {
			<-a.fetchSlots
		}
		return call, nil
	}
	if haveSlot {
		call := &tokenCall{done: make(chan struct{})}
		a.inflight[key] = call
		a.tokenMu.Unlock()
		go a.fetchToken(key, audiences, call)
		return call, nil
	}
	a.tokenMu.Unlock()

	select {
	case a.fetchSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	// Another caller may have fetched the token while this one waited.
	return a.joinOrStart(ctx, key, audiences, true)
}

// freshToken returns the cached token for key if it has more than half its
// lifetime left. The caller holds tokenMu.
func (a *Agent) freshToken(key string) (Token, bool) {
	t, ok := a.tokens[key]
	return t, ok && time.Now().Before(t.Expires.Add(-t.Lifetime/2))
}

// singleUseToken fetches a token for the management endpoint, which is
// neither cached nor shared: the issuer accepts a management token for one
// write only (SPEC section 8.1), so each caller needs its own.
func (a *Agent) singleUseToken(ctx context.Context, audiences []string) (Token, error) {
	select {
	case a.fetchSlots <- struct{}{}:
	case <-ctx.Done():
		return Token{}, status.FromContextError(ctx.Err()).Err()
	}
	defer func() { <-a.fetchSlots }()
	t, err := a.issuer.FetchToken(ctx, a.cred, audiences)
	if err != nil {
		return Token{}, a.fetchError(err, audiences)
	}
	a.tokenMu.Lock()
	a.id = t.SPIFFEID
	a.tokenMu.Unlock()
	return t, nil
}

// fetchError logs why a token request failed and turns the failure into
// the Workload API's status (SPEC section 9).
func (a *Agent) fetchError(err error, audiences []string) error {
	var rejected *RejectedError
	var local *CredentialError
	switch {
	case errors.As(err, &rejected):
		a.logger.Warn("the issuer refused a token request", "audience", audiences, "error", err)
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &local):
		a.logger.Error("the workload credential failed", "error", err)
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	a.logger.Warn("fetching a token failed", "audience", audiences, "error", err)
	return status.Error(codes.Unavailable, "the issuer is unavailable")
}

// fetchToken runs one token request on behalf of everyone waiting on call.
// It does not use any caller's context: a caller giving up must not fail the
// request for the others.
func (a *Agent) fetchToken(key string, audiences []string, call *tokenCall) {
	defer func() { <-a.fetchSlots }()
	t, err := a.issuer.FetchToken(context.Background(), a.cred, audiences)
	if err != nil {
		call.err = a.fetchError(err, audiences)
	}
	call.token = t

	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	delete(a.inflight, key)
	if err == nil {
		if len(a.tokens) >= maxTokenCacheEntries {
			clear(a.tokens)
		}
		a.id = t.SPIFFEID
		// A token whose key left the bundle while it was being fetched is
		// returned to those waiting but not kept, or the cache would serve a
		// revoked token the refresh that dropped its key already missed.
		if a.signedByCurrentKey(t) {
			a.tokens[key] = t
		}
	}
	close(call.done)
}

// FetchJWTBundles streams the trust domain's JWT bundle and every update.
func (a *Agent) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	bundle, changed := a.currentBundle()
	for bundle == nil {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-changed:
			bundle, changed = a.currentBundle()
		}
	}
	var sent []byte
	for {
		jwks, err := marshalJWTBundle(bundle)
		if err != nil {
			return status.Error(codes.Internal, "encoding the bundle failed")
		}
		// X.509 authorities share the notification; they are no news here.
		if !bytes.Equal(jwks, sent) {
			resp := &workload.JWTBundlesResponse{
				Bundles: map[string][]byte{bundle.TrustDomain().IDString(): jwks},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			sent = jwks
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			bundle, changed = a.currentBundle()
		}
	}
}

// marshalJWTBundle encodes the bundle's JWT authorities as a JWKS, each key
// marked for JWT-SVIDs, in a stable order.
func marshalJWTBundle(bundle *spiffebundle.Bundle) ([]byte, error) {
	authorities := bundle.JWTAuthorities()
	ids := make([]string, 0, len(authorities))
	for id := range authorities {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	jwks := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(ids))}
	for _, id := range ids {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{Key: authorities[id], KeyID: id, Use: "jwt-svid"})
	}
	return json.Marshal(jwks)
}

// ValidateJWTSVID validates a JWT-SVID against the trust bundle.
func (a *Agent) ValidateJWTSVID(_ context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if req.Audience == "" {
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}
	if req.Svid == "" {
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}
	bundle, _ := a.currentBundle()
	if bundle == nil {
		return nil, status.Error(codes.Unavailable, "the trust bundle is not available yet")
	}
	jwtBundle := jwtbundle.FromJWTAuthorities(bundle.TrustDomain(), bundle.JWTAuthorities())
	svid, err := jwtsvid.ParseAndValidate(req.Svid, jwtBundle, []string{req.Audience})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if iss, _ := svid.Claims["iss"].(string); iss != a.issuer.URL() {
		return nil, status.Errorf(codes.InvalidArgument, "issued by %q, not %q", truncate(iss, 128), a.issuer.URL())
	}
	claims, err := structpb.NewStruct(normalizeClaims(svid.Claims))
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("encoding claims: %v", err))
	}
	return &workload.ValidateJWTSVIDResponse{SpiffeId: svid.ID.String(), Claims: claims}, nil
}

// normalizeClaims converts claim values into the types structpb accepts.
// go-jose decodes numeric dates into a type of its own, and an audience into
// a []string.
func normalizeClaims(claims map[string]any) map[string]any {
	data, err := json.Marshal(claims)
	if err != nil {
		return claims
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return claims
	}
	return out
}
