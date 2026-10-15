package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// jwksRefresh is how long fetched keys are used before they are fetched
	// again.
	jwksRefresh = 10 * time.Minute
	// jwksMinRefetch rate-limits fetches triggered by a token naming a key
	// that is not in the cached set, which anyone can send.
	jwksMinRefetch = 30 * time.Second
	maxJWKSBody    = 1 << 20
)

// FileKeys reads a JWKS from a file, rereading it when the file changes.
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
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	set, err := parseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	f.set, f.modTime, f.size = set, info.ModTime(), info.Size()
	return set, nil
}

// RemoteKeys fetches a JWKS over HTTPS and caches it.
type RemoteKeys struct {
	// URL is the JWKS location. With Discover set it is instead the
	// upstream's issuer URL, and the JWKS location is read from its OIDC
	// discovery document.
	URL      string
	Discover bool
	// Client makes the requests. It should not follow redirects, and should
	// carry the CA roots the upstream needs.
	Client *http.Client
	// BearerTokenFile, if set, is read for every fetch and sent as a bearer
	// token, only ever to the host of URL. A Kubernetes API server, for one,
	// may require this for its JWKS.
	BearerTokenFile string

	mu         sync.Mutex
	set        *jose.JSONWebKeySet
	fetched    time.Time
	attempted  time.Time
	refreshing chan struct{}
	lastErr    error
}

// jwksMaxStale is how long fetched keys stay usable while the upstream
// cannot be reached. After that the exchange fails closed rather than keep
// trusting keys the upstream may have withdrawn.
const jwksMaxStale = 24 * time.Hour

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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	set, err := r.fetch(ctx)

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
	jwksURL := r.URL
	if r.Discover {
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		data, err := r.get(ctx, strings.TrimSuffix(r.URL, "/")+"/.well-known/openid-configuration")
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
		if doc.Issuer != r.URL || doc.JWKSURI == "" {
			return nil, fmt.Errorf("discovery: issuer %q or jwks_uri %q does not fit %s", doc.Issuer, doc.JWKSURI, r.URL)
		}
		jwksURL = doc.JWKSURI
	}
	data, err := r.get(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	return parseJWKS(data)
}

func (r *RemoteKeys) get(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s: only https is allowed", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if r.BearerTokenFile != "" {
		// A discovery document may point anywhere; the credential goes only
		// where the operator configured.
		configured, err := url.Parse(r.URL)
		if err != nil {
			return nil, err
		}
		if u.Host != configured.Host {
			return nil, fmt.Errorf("%s: not sending the bearer token to a host other than %s", rawURL, configured.Host)
		}
		token, err := os.ReadFile(r.BearerTokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody))
}

// parseJWKS parses a key set and keeps only public signing keys.
func parseJWKS(data []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
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
