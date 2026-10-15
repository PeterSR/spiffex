package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/PeterSR/spiffex/internal/issuer"
)

// Registry serves client registrations from a configuration file and picks
// up changes to them while the issuer runs, including changes to the public
// key files the configuration refers to. Upstream changes wait for a restart
// while client changes in the same edit apply at once. Other settings take
// effect only on restart; a change to them is refused.
type Registry struct {
	path    string
	logger  *slog.Logger
	current atomic.Pointer[Loaded]

	// Only Run and Reload touch these, and never concurrently.
	applied [sha256.Size]byte
	seen    [sha256.Size]byte
	refused [sha256.Size]byte
	hasSeen bool
	lastErr string
	// pendingUpstreams is an upstream edit already warned about.
	pendingUpstreams []UpstreamConfig
}

// NewRegistry loads the configuration file at path.
func NewRegistry(path string, logger *slog.Logger) (*Registry, error) {
	if logger == nil {
		logger = slog.Default()
	}
	loaded, digest, err := loadWithDigest(path)
	if err != nil {
		return nil, err
	}
	r := &Registry{path: path, logger: logger, applied: digest}
	r.current.Store(loaded)
	return r, nil
}

// loadWithDigest loads the file and hashes it together with every public key
// file it refers to.
func loadWithDigest(path string) (*Loaded, [sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	loaded, err := parseFile(path, data)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	digest, err := digestOf(data, loaded.keyFiles)
	return loaded, digest, err
}

func digestOf(config []byte, keyFiles []string) ([sha256.Size]byte, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n", len(config))
	h.Write(config)
	for _, f := range keyFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		fmt.Fprintf(h, "%s\n%d\n", f, len(data))
		h.Write(data)
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// Client implements issuer.ClientSource.
func (r *Registry) Client(id string) (issuer.Client, bool) {
	c, ok := r.current.Load().Clients[id]
	return c, ok
}

// Config returns the configuration currently in service.
func (r *Registry) Config() *Loaded { return r.current.Load() }

// Reload rereads the configuration and applies it at once, without the
// stability wait Run uses, and reports whether it changed. A file that fails
// to load, or changes a restart-only setting, leaves the previous
// registrations in service.
func (r *Registry) Reload() (bool, error) {
	next, digest, err := loadWithDigest(r.path)
	if err != nil {
		return false, err
	}
	return r.apply(next, digest)
}

func (r *Registry) apply(next *Loaded, digest [sha256.Size]byte) (bool, error) {
	if digest == r.applied {
		return false, nil
	}
	prev := r.current.Load()
	if !sameRestartSettings(prev, next) {
		return false, errors.New("issuer, trust_domain, keys_dir, token_ttl and activation_delay only change on restart")
	}
	if !reflect.DeepEqual(prev.upstreamsRaw, next.upstreamsRaw) {
		// The client changes still apply: holding back, say, the removal of
		// a compromised key until a restart would be worse.
		if !reflect.DeepEqual(r.pendingUpstreams, next.upstreamsRaw) {
			r.logger.Warn("upstreams changed; the change takes effect when the issuer restarts")
			r.pendingUpstreams = next.upstreamsRaw
		}
		next.Upstreams, next.upstreamsRaw = prev.Upstreams, prev.upstreamsRaw
	}
	r.current.Store(next)
	r.applied = digest
	for id := range prev.Clients {
		if _, kept := next.Clients[id]; !kept {
			r.logger.Warn("client removed from the configuration", "client_id", id)
		}
	}
	return true, nil
}

func sameRestartSettings(a, b *Loaded) bool {
	effective := func(d, def time.Duration) time.Duration {
		if d == 0 {
			return def
		}
		return d
	}
	return a.Issuer == b.Issuer && a.TrustDomain == b.TrustDomain && a.KeysDir == b.KeysDir &&
		effective(a.TokenTTL, issuer.DefaultTokenTTL) == effective(b.TokenTTL, issuer.DefaultTokenTTL) &&
		effective(a.ActivationDelay, issuer.DefaultActivationDelay) == effective(b.ActivationDelay, issuer.DefaultActivationDelay)
}

// Run checks the configuration every interval until ctx is done. A change is
// applied once it has stayed the same for two checks in a row, so a file
// caught halfway through being written is not taken for the new
// configuration.
func (r *Registry) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.check()
		}
	}
}

func (r *Registry) check() {
	next, digest, err := loadWithDigest(r.path)
	if err != nil {
		r.hasSeen = false
		if err.Error() != r.lastErr {
			r.lastErr = err.Error()
			r.logger.Error("the configuration does not load, keeping the previous clients", "error", err)
		}
		return
	}
	r.lastErr = ""
	if digest == r.applied {
		r.hasSeen = false
		return
	}
	if !r.hasSeen || digest != r.seen {
		r.seen, r.hasSeen = digest, true
		return
	}
	r.hasSeen = false
	if digest == r.refused {
		return
	}
	changed, err := r.apply(next, digest)
	switch {
	case err != nil:
		// Log a refused configuration once, not on every check.
		r.refused = digest
		r.logger.Error("not applying the changed configuration", "error", err)
	case changed:
		r.logger.Info("configuration reloaded", "clients", len(r.current.Load().Clients))
	}
}
