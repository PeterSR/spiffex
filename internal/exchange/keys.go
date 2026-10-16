package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Limits on fetching an upstream's keys (SPEC section 5.2).
const (
	// jwksRefresh is how long fetched keys are used before they are fetched
	// again.
	jwksRefresh = 10 * time.Minute
	// jwksMinRefetch rate-limits fetches triggered by a token naming a key
	// that is not in the cached set, which anyone can send.
	jwksMinRefetch = 30 * time.Second
	// jwksMaxStale is how long fetched keys stay usable while the upstream
	// cannot be reached. After that exchanges fail closed rather than keep
	// trusting keys the upstream may have withdrawn.
	jwksMaxStale = 24 * time.Hour
	fetchTimeout = 15 * time.Second
	maxJWKSBody  = 1 << 20
	maxJWKSKeys  = 100
)

// KeySource supplies an upstream's public keys.
type KeySource interface {
	// Keys returns the current key set. kid is the key the token names, so an
	// implementation can refresh when it does not know it.
	Keys(ctx context.Context, kid string) (*jose.JSONWebKeySet, error)
}

// StaticKeys is a key set written into the state.
type StaticKeys struct {
	Set *jose.JSONWebKeySet
}

// Keys implements KeySource.
func (s StaticKeys) Keys(context.Context, string) (*jose.JSONWebKeySet, error) { return s.Set, nil }

// FileKeys reads a JWK Set from a local file, rereading it when the file
// changes.
type FileKeys struct {
	Path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	set     *jose.JSONWebKeySet
}

// Keys implements KeySource.
func (f *FileKeys) Keys(context.Context, string) (*jose.JSONWebKeySet, error) {
	info, err := os.Stat(f.Path)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.set != nil && info.ModTime().Equal(f.modTime) && info.Size() == f.size {
		return f.set, nil
	}
	file, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := readBounded(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	set, err := parseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	f.set, f.modTime, f.size = set, info.ModTime(), info.Size()
	return set, nil
}

// RemoteKeys fetches a JWK Set over HTTPS and caches it. Fetches never
// follow redirects, are limited in size and time, and with
// RefusePrivateAddresses never connect to an address that is not public.
type RemoteKeys struct {
	// URL is the JWK Set's location. With Discover set it is instead the
	// upstream's issuer URL, and the JWK Set's location is read from its
	// OIDC discovery document, whose issuer must equal it.
	URL      string
	Discover bool
	// CAFile, if set, holds the CA certificates to trust instead of the
	// system roots. It is read for every fetch.
	CAFile string
	// BearerTokenFile, if set, is read for every fetch and sent as a bearer
	// token, but only to a host in BearerHosts, and only to the host of URL:
	// with Discover, only with the discovery request, never to the JWK Set
	// location the discovery document names.
	BearerTokenFile string
	BearerHosts     []string
	// BearerPaths, when set, further limits the token to URLs with one of
	// these paths and no query.
	BearerPaths []string
	// RefusePrivateAddresses refuses connections to loopback, link-local,
	// private and other non-public addresses, except for the host:port
	// pairs in AllowPrivateHosts.
	RefusePrivateAddresses bool
	AllowPrivateHosts      []string

	mu         sync.Mutex
	set        *jose.JSONWebKeySet
	fetched    time.Time
	attempted  time.Time
	refreshing chan struct{}
	lastErr    error
}

// Keys implements KeySource. It refreshes in the background when the cached
// set is old, or when the token names a key the set lacks (at most every
// jwksMinRefetch), and serves the cached set meanwhile. Without a cached set
// it waits for the fetch as long as ctx allows.
func (r *RemoteKeys) Keys(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	r.mu.Lock()
	now := time.Now()
	set := r.set
	if set != nil && now.Sub(r.fetched) > jwksMaxStale {
		set = nil
	}
	unknown := set != nil && kid != "" && len(set.Key(kid)) == 0
	var due bool
	switch {
	case set == nil:
		due = now.Sub(r.attempted) >= time.Second
	case now.Sub(r.fetched) > jwksRefresh:
		due = now.Sub(r.attempted) >= jwksMinRefetch
	case unknown:
		due = now.Sub(r.attempted) >= jwksMinRefetch
	}
	if due && r.refreshing == nil {
		r.refreshing = make(chan struct{})
		go r.refresh(r.refreshing)
	}
	wait, lastErr := r.refreshing, r.lastErr
	r.mu.Unlock()

	// A token naming a key the cache lacks is likely the first signed after
	// the upstream rotated: wait for the refresh rather than refuse it.
	if set != nil && !(unknown && wait != nil) {
		return set, nil
	}
	if wait == nil {
		if lastErr == nil {
			lastErr = errors.New("upstream keys are not available")
		}
		return nil, lastErr
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-wait:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set == nil || time.Since(r.fetched) > jwksMaxStale {
		if set != nil {
			return set, nil
		}
		return nil, r.lastErr
	}
	return r.set, nil
}

// refresh fetches the keys on behalf of every caller. It does not use any
// caller's context: one caller giving up must not leave the cache stale.
func (r *RemoteKeys) refresh(done chan struct{}) {
	set, err := r.fetch(context.Background())

	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempted = time.Now()
	r.lastErr = err
	if err == nil {
		r.set, r.fetched = set, r.attempted
	}
	r.refreshing = nil
	close(done)
}

func (r *RemoteKeys) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	jwksURL := r.URL
	if r.Discover {
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		data, err := r.get(ctx, client, strings.TrimSuffix(r.URL, "/")+"/.well-known/openid-configuration", true)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
		if doc.Issuer != r.URL || doc.JWKSURI == "" {
			return nil, fmt.Errorf("discovery: issuer %q or jwks_uri %q does not fit %s", doc.Issuer, doc.JWKSURI, r.URL)
		}
		data, err = r.get(ctx, client, doc.JWKSURI, false)
		if err != nil {
			return nil, err
		}
		return parseJWKS(data)
	}
	data, err := r.get(ctx, client, jwksURL, true)
	if err != nil {
		return nil, err
	}
	return parseJWKS(data)
}

func (r *RemoteKeys) client() (*http.Client, error) {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = dialer.DialContext
	if r.RefusePrivateAddresses {
		checked := &net.Dialer{Timeout: 10 * time.Second, Control: refusePrivate}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if hostPortIn(addr, r.AllowPrivateHosts) {
				return dialer.DialContext(ctx, network, addr)
			}
			return checked.DialContext(ctx, network, addr)
		}
		// Through a proxy the address dialled is the proxy's, which says
		// nothing about where the request goes.
		transport.Proxy = nil
	}
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificates", r.CAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// get fetches one document. mayAuthenticate says whether the bearer token
// may go with this request at all; it then goes only to an allowed host.
func (r *RemoteKeys) get(ctx context.Context, client *http.Client, rawURL string, mayAuthenticate bool) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%s: only https is allowed", rawURL)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if mayAuthenticate && r.BearerTokenFile != "" && r.bearerAllowed(u) {
		token, err := os.ReadFile(r.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("reading the bearer token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	data, err := readBounded(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	return data, nil
}

func (r *RemoteKeys) bearerAllowed(u *url.URL) bool {
	if !hostIn(u.Host, r.BearerHosts) {
		return false
	}
	return len(r.BearerPaths) == 0 || u.RawQuery == "" && slices.Contains(r.BearerPaths, u.Path)
}

// hostPortIn reports whether addr, the host and port a URL names, is one of
// hostPorts, comparing host names without regard to case.
func hostPortIn(addr string, hostPorts []string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	for _, hp := range hostPorts {
		h, p, err := net.SplitHostPort(hp)
		if err == nil && p == port && strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func hostIn(host string, hosts []string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxJWKSBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJWKSBody {
		return nil, fmt.Errorf("larger than %d bytes", maxJWKSBody)
	}
	return data, nil
}

// parseJWKS parses a key set and keeps only public signing keys. Its errors
// never quote the content, which may come from a local file.
func parseJWKS(data []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("not a JWK Set")
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("the key set has %d keys, more than the %d allowed", len(set.Keys), maxJWKSKeys)
	}
	out := &jose.JSONWebKeySet{}
	for _, k := range set.Keys {
		if k.IsPublic() && k.Valid() && (k.Use == "" || k.Use == "sig") {
			out.Keys = append(out.Keys, k)
		}
	}
	if len(out.Keys) == 0 {
		return nil, errors.New("the key set has no public signing keys")
	}
	return out, nil
}
