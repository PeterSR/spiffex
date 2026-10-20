package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand/v2"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// renewFrom and renewTo bound the part of an X.509-SVID's lifetime at
	// which it is renewed; where in between is random (SPEC section 9).
	renewFrom = 0.40
	renewTo   = 0.50
	// minLifeLeft is the fraction of its lifetime an X.509-SVID must have
	// left to be sent to a workload.
	minLifeLeft = 0.10
	// refusalTTL is how long the agent answers with an issuer's refusal
	// without asking again: long enough that a workload retrying in a loop
	// costs the issuer one request a minute, short enough that a corrected
	// origin is noticed soon.
	refusalTTL = time.Minute
	// minRetry and maxRetry bound the wait between failed requests, which
	// doubles from the first to the second.
	minRetry = time.Second
	maxRetry = time.Minute
	// maxRenewFloor caps the shortest wait between two requests that succeed.
	maxRenewFloor = 30 * time.Second
)

// x509Material is the agent's current X.509-SVID in the shapes the Workload
// API sends. It is never modified once made.
type x509Material struct {
	id        spiffeid.ID
	certs     []*x509.Certificate
	chain     []byte // DER, the workload's certificate first
	key       []byte // PKCS#8 DER
	serial    *big.Int
	notBefore time.Time
	notAfter  time.Time
	renewAt   time.Time
	// earliest is the floor after receipt that no request comes before.
	earliest time.Time
}

// usable reports whether the SVID has the part of its life left that lets
// the agent send it.
func (m *x509Material) usable(now time.Time) bool {
	return now.Before(m.notAfter.Add(-time.Duration(float64(m.notAfter.Sub(m.notBefore)) * minLifeLeft)))
}

// renewalTime places the renewal inside the window; position is in [0, 1).
func renewalTime(notBefore, notAfter time.Time, position float64) time.Time {
	life := float64(notAfter.Sub(notBefore))
	return notBefore.Add(time.Duration(life * (renewFrom + (renewTo-renewFrom)*position)))
}

// scheduleRenewal returns when to renew an SVID received at received. The
// window is measured on the certificate's own clock and again on the agent's
// from the moment of receipt, and the earlier counts; the result is never
// sooner than a floor after receipt, so a clock that disagrees with the
// issuer's cannot turn renewal into a loop. skewed reports that the
// certificate was already due, or not yet valid, by the agent's clock.
func scheduleRenewal(notBefore, notAfter, received time.Time, position float64) (at time.Time, skewed bool) {
	byCert := renewalTime(notBefore, notAfter, position)
	byAgent := received.Add(time.Duration(float64(notAfter.Sub(received)) * (renewFrom + (renewTo-renewFrom)*position)))
	at = byCert
	if byAgent.Before(at) {
		at = byAgent
	}
	skewed = !byCert.After(received) || notBefore.After(received)
	return later(at, received.Add(renewFloor(notBefore, notAfter))), skewed
}

// renewFloor is the shortest wait after receiving an SVID before asking for
// the next: a tenth of its lifetime, at most 30 s, never zero.
func renewFloor(notBefore, notAfter time.Time) time.Duration {
	return max(min(notAfter.Sub(notBefore)/10, maxRenewFloor), time.Millisecond)
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// x509Hub holds the one X.509-SVID the agent has for its workload and keeps
// it fresh while any stream is open. Every stream reads the same SVID, so
// they share one key and one certificate.
type x509Hub struct {
	agent *Agent

	// Tuning, replaced by tests before any stream opens.
	now        func() time.Time
	jitter     func() float64
	minRetry   time.Duration
	maxRetry   time.Duration
	refusalTTL time.Duration

	mu      sync.Mutex
	svid    *x509Material
	refusal error // the issuer's refusal, as a status, until refusedTo
	// refusedTo is when the refusal stops being repeated.
	refusedTo time.Time
	// credErr is a failure to produce the workload's proof, set by the loop
	// numbered credGen. Only the loop in service may answer with it, so an
	// error from before the last pause is never repeated to a new stream.
	credErr error
	credGen int
	// nextAttempt and retry (zero after a success) are the schedule of requests to the issuer. They
	// live here, not in the loop, so streams coming and going cannot reset
	// the backoff or start requests ahead of it.
	nextAttempt time.Time
	retry       time.Duration
	// changed is closed, and replaced, whenever the fields above change.
	changed chan struct{}
	// kick wakes a sleeping loop to look at nextAttempt again.
	kick    chan struct{}
	streams int
	// cancel stops the renewal loop while it sleeps; nil when none runs. gen
	// numbers the loops, and fetching is set while one request is in flight,
	// which no one cancels.
	cancel   context.CancelFunc
	gen      int
	fetching bool
	// pair caches the last check of an SVID against a bundle.
	pair struct {
		svid   *x509Material
		bundle *spiffebundle.Bundle
		ok     bool
	}
}

func newX509Hub(a *Agent) *x509Hub {
	return &x509Hub{
		agent:      a,
		now:        time.Now,
		jitter:     mathrand.Float64,
		minRetry:   minRetry,
		maxRetry:   maxRetry,
		refusalTTL: refusalTTL,
		changed:    make(chan struct{}),
		kick:       make(chan struct{}, 1),
	}
}

// x509View is what a stream sees of the hub at one moment.
type x509View struct {
	svid    *x509Material
	refusal error
	credErr error
	changed <-chan struct{}
}

func (h *x509Hub) view() x509View {
	h.mu.Lock()
	defer h.mu.Unlock()
	var credErr error
	if h.credGen == h.gen {
		credErr = h.credErr
	}
	return x509View{h.svid, h.refusalLocked(), credErr, h.changed}
}

func (h *x509Hub) notifyLocked() {
	close(h.changed)
	h.changed = make(chan struct{})
}

// refusalLocked returns the issuer's refusal while it is still repeated.
func (h *x509Hub) refusalLocked() error {
	if h.refusal != nil && !h.now().Before(h.refusedTo) {
		h.refusal = nil
	}
	return h.refusal
}

// attach registers a stream and makes sure the SVID is being kept fresh. It
// fails with the issuer's refusal while that is remembered, without asking
// the issuer. The returned function unregisters the stream; with the last
// one gone the renewal stops once any request in flight is done, and the
// SVID stays for the next stream.
func (h *x509Hub) attach() (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.refusalLocked(); err != nil {
		return nil, err
	}
	h.streams++
	if h.cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		h.cancel = cancel
		h.gen++
		go h.run(ctx, h.gen)
	}
	return h.detach, nil
}

func (h *x509Hub) detach() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams--
	if h.streams == 0 && h.cancel != nil && !h.fetching {
		h.cancel()
		h.cancel = nil
	}
}

// expedite brings the next request forward, for an SVID that no longer
// chains to the bundle, but not before the floor after the last SVID was
// received, so a bundle that flaps cannot make renewal a loop. A schedule of
// retries after failures is left alone.
func (h *x509Hub) expedite() {
	h.mu.Lock()
	defer h.mu.Unlock()
	at := h.now()
	if h.svid != nil {
		at = later(at, h.svid.earliest)
	}
	if h.retry == 0 && h.nextAttempt.After(at) {
		h.nextAttempt = at
		select {
		case h.kick <- struct{}{}:
		default:
		}
	}
}

// exitLocked ends the loop numbered gen if it is still the one in service.
func (h *x509Hub) exitLocked(gen int) {
	if h.gen == gen && h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
}

// run keeps the SVID current: it waits for the next attempt, requests a new
// SVID with a new key, and schedules the next attempt, by the SVID's
// renewal time or by backoff after a failure. A request in flight is always
// finished and its result kept, also when the last stream has left; the loop
// stops at the next decision. A refusal ends it.
func (h *x509Hub) run(ctx context.Context, gen int) {
	for {
		h.mu.Lock()
		wait := h.nextAttempt.Sub(h.now())
		h.mu.Unlock()
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-h.kick:
				t.Stop()
				continue
			case <-t.C:
			}
		}

		h.mu.Lock()
		if ctx.Err() != nil {
			h.mu.Unlock()
			return
		}
		if h.streams == 0 || !h.agent.issuer.X509Supported() {
			h.exitLocked(gen)
			h.mu.Unlock()
			return
		}
		h.fetching = true
		h.mu.Unlock()

		m, err := h.fetch(context.Background())

		var rejected *RejectedError
		var local *CredentialError
		h.mu.Lock()
		h.fetching = false
		switch {
		case err == nil:
			h.svid, h.credErr = m, nil
			h.retry = 0
			h.nextAttempt = m.renewAt
			h.notifyLocked()
			h.mu.Unlock()
			h.agent.setIdentity(m.id)
			h.agent.logger.Info("obtained an X.509-SVID", "spiffe_id", m.id.String(), "serial", m.serial.Text(16), "not_after", m.notAfter, "renew_at", m.renewAt)
			h.mu.Lock()
		case errors.As(err, &rejected):
			// The identity is withdrawn or was never allowed: nothing is
			// served, and nothing is asked again for a while.
			h.svid, h.credErr = nil, nil
			h.retry = 0
			h.refusal = status.Error(codes.PermissionDenied, err.Error())
			h.refusedTo = h.now().Add(h.refusalTTL)
			h.nextAttempt = h.refusedTo
			h.exitLocked(gen)
			h.notifyLocked()
			h.mu.Unlock()
			h.agent.logger.Warn("the issuer refused an X.509-SVID request", "error", err, "repeated_for", h.refusalTTL)
			return
		default:
			retry := max(h.retry, h.minRetry)
			wait := retry/2 + time.Duration(h.jitter()*float64(retry/2))
			h.nextAttempt = h.now().Add(wait)
			if errors.As(err, &local) {
				h.agent.logger.Error("the workload credential failed", "error", err, "retry_in", wait)
				h.credErr, h.credGen = status.Error(codes.FailedPrecondition, err.Error()), gen
			} else {
				h.agent.logger.Warn("fetching an X.509-SVID failed", "error", err, "retry_in", wait)
				h.credErr = nil
			}
			h.retry = min(retry*2, h.maxRetry)
			h.notifyLocked()
		}
		if h.streams == 0 {
			h.exitLocked(gen)
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
	}
}

// fetch makes a key and has the issuer certify it. The certificate must chain
// to the bundle the workloads will be given, or it is no use to them.
func (h *x509Hub) fetch(ctx context.Context) (*x509Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("making a key: %w", err)
	}
	svid, err := h.agent.issuer.FetchX509SVID(ctx, h.agent.cred, key)
	if err != nil {
		return nil, err
	}
	if err := h.agent.verifyX509(ctx, svid.Chain, h.now); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding the key: %w", err)
	}
	var chain []byte
	for _, cert := range svid.Chain {
		chain = append(chain, cert.Raw...)
	}
	leaf := svid.Chain[0]
	received := h.now()
	renewAt, skewed := scheduleRenewal(leaf.NotBefore, leaf.NotAfter, received, h.jitter())
	if skewed {
		h.agent.logger.Warn("the clock of this host and the issuer's disagree: the X.509-SVID is already due for renewal, or not yet valid",
			"not_before", leaf.NotBefore, "not_after", leaf.NotAfter, "now", received, "renew_at", renewAt)
	}
	return &x509Material{
		id: svid.SPIFFEID, certs: svid.Chain, chain: chain, key: der, serial: leaf.SerialNumber,
		notBefore: leaf.NotBefore, notAfter: leaf.NotAfter, renewAt: renewAt,
		earliest: received.Add(renewFloor(leaf.NotBefore, leaf.NotAfter)),
	}, nil
}

// verifyChain checks the chain against the bundle's X.509 authorities. The
// time is the later of now and the leaf's notBefore: the client accepts a
// certificate starting up to clockSkew ahead of this clock, and
// workloads do not check their own SVID's validity.
func verifyChain(chain []*x509.Certificate, bundle *spiffebundle.Bundle, now time.Time) error {
	if bundle == nil {
		return errors.New("no trust bundle yet")
	}
	at := later(now, chain[0].NotBefore)
	_, _, err := x509svid.Verify(chain, x509bundle.FromX509Authorities(bundle.TrustDomain(), bundle.X509Authorities()), x509svid.WithTime(at))
	return err
}

// verifyX509 checks a new chain against the agent's bundle. A bundle that
// predates a new CA fails it, so the bundle is fetched again once before the
// chain is held against the issuer.
func (a *Agent) verifyX509(ctx context.Context, chain []*x509.Certificate, now func() time.Time) error {
	verify := func() error {
		bundle, _ := a.currentBundle()
		return verifyChain(chain, bundle, now())
	}
	if verify() == nil {
		return nil
	}
	a.refreshBundle(ctx)
	if err := verify(); err != nil {
		return fmt.Errorf("the issuer's X.509-SVID does not verify against its bundle: %w", err)
	}
	return nil
}

// pairOK reports whether the SVID chains to the bundle it would be sent with,
// remembering the answer for the pair. A pair that fails (an anchor was
// retired under the SVID) is not sent, and brings the renewal forward.
func (h *x509Hub) pairOK(m *x509Material, bundle *spiffebundle.Bundle) bool {
	h.mu.Lock()
	if h.pair.svid == m && h.pair.bundle == bundle {
		ok := h.pair.ok
		h.mu.Unlock()
		return ok
	}
	h.mu.Unlock()
	ok := verifyChain(m.certs, bundle, h.now()) == nil
	h.mu.Lock()
	h.pair.svid, h.pair.bundle, h.pair.ok = m, bundle, ok
	h.mu.Unlock()
	if !ok {
		h.agent.logger.Warn("the X.509-SVID no longer chains to the trust bundle, renewing it", "serial", m.serial.Text(16))
	}
	return ok
}

func (a *Agent) setIdentity(id spiffeid.ID) {
	a.tokenMu.Lock()
	a.id = id
	a.tokenMu.Unlock()
}

// x509Unsupported is the answer when the issuer has no certificate authority.
func x509Unsupported() error {
	return status.Error(codes.Unimplemented, "the issuer does not issue X.509-SVIDs")
}

// x509Authorities returns the bundle's X.509 authorities as the Workload
// API sends them: DER, concatenated.
func x509Authorities(b *spiffebundle.Bundle) []byte {
	var out []byte
	for _, cert := range b.X509Authorities() {
		out = append(out, cert.Raw...)
	}
	return out
}

// FetchX509SVID streams the workload's X.509-SVID, with the trust domain's
// X.509 bundle, and every renewal.
func (a *Agent) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	if !a.issuer.X509Supported() {
		return x509Unsupported()
	}
	detach, err := a.x509.attach()
	if err != nil {
		return err
	}
	defer detach()

	var sentSVID *x509Material
	var sentBundle *spiffebundle.Bundle
	for {
		view := a.x509.view()
		bundle, bundleChanged := a.currentBundle()
		switch {
		case !a.issuer.X509Supported():
			return x509Unsupported()
		case view.refusal != nil:
			return view.refusal
		}

		// The bundle is held back until it has X.509 authorities, as the
		// JWT bundle is until it has keys: a workload given none could
		// verify nobody.
		ready := bundle != nil && len(bundle.X509Authorities()) > 0
		send := false
		if view.svid != nil && view.svid.usable(a.x509.now()) && ready {
			if a.x509.pairOK(view.svid, bundle) {
				send = true
			} else {
				a.x509.expedite()
			}
		}
		if send {
			if view.svid != sentSVID || !sameX509Authorities(bundle, sentBundle) {
				resp := &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{
					SpiffeId:    view.svid.id.String(),
					X509Svid:    view.svid.chain,
					X509SvidKey: view.svid.key,
					Bundle:      x509Authorities(bundle),
				}}}
				if err := stream.Send(resp); err != nil {
					return err
				}
				sentSVID, sentBundle = view.svid, bundle
			}
		} else if view.credErr != nil {
			return view.credErr
		}

		select {
		case <-ctx.Done():
			if sentSVID == nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			return nil
		case <-view.changed:
		case <-bundleChanged:
		}
	}
}

// FetchX509Bundles streams the X.509 authorities of the trust domain's
// bundle and every change to them.
func (a *Agent) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	if !a.issuer.X509Supported() {
		return x509Unsupported()
	}
	var sent *spiffebundle.Bundle
	for {
		bundle, changed := a.currentBundle()
		if !a.issuer.X509Supported() {
			return x509Unsupported()
		}
		if bundle != nil && len(bundle.X509Authorities()) > 0 && (sent == nil || !sameX509Authorities(bundle, sent)) {
			resp := &workload.X509BundlesResponse{
				Bundles: map[string][]byte{bundle.TrustDomain().IDString(): x509Authorities(bundle)},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			sent = bundle
		}
		select {
		case <-ctx.Done():
			if sent == nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			return nil
		case <-changed:
		}
	}
}
