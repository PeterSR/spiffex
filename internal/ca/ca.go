// Package ca holds the issuer's certificate authority: the CA certificates
// and keys it signs X.509-SVIDs with, the anchors the bundle publishes, and
// the rules that choose between them (SPEC section 2.5).
//
// The CA directory holds one pair of files per CA generation, named after the
// moment the generation was made:
//
//	ca-20261015T120000Z.crt   PEM: the signing CA certificate, then the CA
//	                          certificates between it and its anchor, if any
//	ca-20261015T120000Z.key   PEM: its private key (PKCS#8, SEC 1 or PKCS#1)
//
// A self-signed certificate is its own anchor. A certificate without a key is
// accepted only when it is self-signed, as an anchor that is published and
// not signed with. A key without a certificate is a pending request (spiffex
// ca csr) and is ignored. The operator's own roots are not kept here but in
// the file ca_roots.
package ca

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/PeterSR/spiffex/internal/rotation"
)

// Limits on what the CA signs.
const (
	// MinLifetime is the shortest X.509-SVID the issuer issues: when the
	// chain leaves less than this, it refuses (SPEC section 2.5).
	MinLifetime = 5 * time.Minute
	// ExpiryWarning is how long before the earliest notAfter of the chain
	// the issuer starts warning.
	ExpiryWarning = 30 * 24 * time.Hour
	// ClockSkew is the allowance added to an X.509-SVID lifetime before an
	// anchor is dropped.
	ClockSkew = 10 * time.Minute
)

// Retention returns how long an anchor stays published after the last
// X.509-SVID that chains to it can have been issued (SPEC section 2.5, rule
// 2) for X.509-SVIDs of the given lifetime.
func Retention(svidTTL time.Duration) time.Duration { return svidTTL + ClockSkew }

// ErrNoSigningCA means no CA may sign now: every one is exposed, expired or
// not yet valid.
var ErrNoSigningCA = errors.New("no CA may sign X.509-SVIDs")

// ErrExpiring means the best CA leaves less than MinLifetime.
var ErrExpiring = errors.New("the CA expires too soon to sign an X.509-SVID")

// CA is one CA certificate the issuer can sign with.
type CA struct {
	// ID is the SHA-256 digest of the certificate, in hex.
	ID string
	// Created is the creation time from the file name.
	Created time.Time
	// Published is the earliest moment the certificate can have been seen
	// here: the later of Created and the file's modification time, or later
	// still if a Watcher saw it appear after that.
	Published time.Time
	// Cert is the signing CA certificate; Chain starts with it and goes on
	// with the CA certificates between it and Anchor, which is not in it.
	Cert   *x509.Certificate
	Chain  []*x509.Certificate
	Anchor *x509.Certificate
	Signer crypto.Signer
	// File and KeyFile are the base names of the certificate and key files.
	File, KeyFile string
	// Exposed marks a key that someone other than the issuer may have been
	// able to read. The certificate stays published, but never signs again.
	Exposed bool
}

// SelfSigned reports whether the CA is its own anchor.
func (c CA) SelfSigned() bool { return c.Cert.Equal(c.Anchor) }

// notBefore and notAfter bound the time the whole chain, anchor included,
// is valid.
func (c CA) notBefore() time.Time {
	t := c.Anchor.NotBefore
	for _, cert := range c.Chain {
		if cert.NotBefore.After(t) {
			t = cert.NotBefore
		}
	}
	return t
}

func (c CA) notAfter() time.Time {
	t := c.Anchor.NotAfter
	for _, cert := range c.Chain {
		if cert.NotAfter.Before(t) {
			t = cert.NotAfter
		}
	}
	return t
}

// NotAfter is the earliest notAfter in the chain up to and including the
// anchor: no X.509-SVID signed by this CA outlives it.
func (c CA) NotAfter() time.Time { return c.notAfter() }

// ValidAt reports whether every certificate of the chain is valid at t.
func (c CA) ValidAt(t time.Time) bool {
	return !t.Before(c.notBefore()) && t.Before(c.notAfter())
}

// Anchor is an X.509 authority: a root certificate that verifiers trust.
type Anchor struct {
	// ID is the SHA-256 digest of the certificate, in hex.
	ID string
	// Cert is the certificate.
	Cert *x509.Certificate
	// Published is the earliest moment verifiers can have learned of it.
	Published time.Time
	// Source is the base name of the file in the CA directory it came from,
	// or RootsSource for the operator's ca_roots file.
	Source string
}

// RootsSource is the Source of anchors read from ca_roots.
const RootsSource = "ca_roots"

func certID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Set is an immutable view of the CA at one moment: the signing CAs, ordered
// by creation time, oldest first, and the anchors. Creation order decides
// which CA is newest; publication time only decides when one may start
// signing.
type Set struct {
	cas       []CA
	anchors   []Anchor
	delay     time.Duration
	anchorPub map[string]time.Time
	revivedAt map[string]time.Time
	// retiredCAs and retiredAnchors hold what retention had ended at the
	// moment the set was built.
	retiredCAs     map[string]bool
	retiredAnchors map[string]bool
}

// newSet builds a set. Every CA's anchor must be among the anchors. now is
// the moment retirement is judged at.
//
// revivedAt holds when the running watcher published an anchor afresh, after it
// had left the bundle: a CA under it does not sign for a delay from then, even
// when the rotation's fallbacks would pick it.
func newSet(cas []CA, anchors []Anchor, delay, retention time.Duration, now time.Time, revivedAt map[string]time.Time) (*Set, error) {
	cas = slices.Clone(cas)
	anchors = slices.Clone(anchors)
	slices.SortFunc(cas, func(a, b CA) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return compareStrings(a.ID, b.ID)
	})
	slices.SortFunc(anchors, func(a, b Anchor) int { return compareStrings(a.ID, b.ID) })
	s := &Set{cas: cas, anchors: anchors, delay: delay, anchorPub: map[string]time.Time{}, revivedAt: revivedAt, retiredCAs: map[string]bool{}, retiredAnchors: map[string]bool{}}
	for i, a := range anchors {
		if i > 0 && anchors[i-1].ID == a.ID {
			return nil, fmt.Errorf("anchor %s appears twice", a.ID)
		}
		s.anchorPub[a.ID] = a.Published
	}
	seen := map[string]bool{}
	for _, c := range cas {
		if seen[c.ID] {
			return nil, fmt.Errorf("CA certificate %s appears twice", c.ID)
		}
		seen[c.ID] = true
		if _, ok := s.anchorPub[certID(c.Anchor)]; !ok {
			return nil, fmt.Errorf("the anchor of %s is missing", c.File)
		}
	}
	s.judgeRetention(retention, now)
	return s, nil
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// effectivePublished is the moment from which an activation delay counts for
// a CA. A root counts from its own publication. An intermediate is never
// published, so it counts from the publication of its anchor: it may sign as
// soon as it appears when that anchor has been published for the delay.
func (s *Set) effectivePublished(c CA) time.Time {
	if c.SelfSigned() {
		return c.Published
	}
	anchor := s.anchorPub[certID(c.Anchor)]
	if own := c.Published.Add(-s.delay); own.After(anchor) {
		return own
	}
	return anchor
}

func (s *Set) entries(include func(CA) bool) (entries []rotation.Entry, index []int) {
	for i, c := range s.cas {
		if include(c) {
			entries = append(entries, rotation.Entry{Created: c.Created, Published: s.effectivePublished(c), Exposed: c.Exposed, Earliest: c.notBefore()})
			index = append(index, i)
		}
	}
	return entries, index
}

// candidates returns the CAs in the running for signing at now, newest first:
// the rotation of SPEC section 2.4 applied to the CAs whose chain has begun to
// be valid, whose key is not exposed and whose anchor is still published. A
// retired CA never signs: its anchor has left the bundle. One whose chain has
// ended is still in the running, so that it keeps ranking newest and an older
// CA does not take over from it: use signer for the one that signs.
func (s *Set) candidates(now time.Time) []CA { return s.eligible(now, true) }

func (s *Set) eligible(now time.Time, skipRetired bool) []CA {
	entries, index := s.entries(func(c CA) bool {
		// The last fallback of the rotation signs with whatever there is, so
		// a CA under an anchor republished less than a delay ago is left out
		// here: verifiers may not have it.
		waiting := skipRetired && s.revivedAt[certID(c.Anchor)].Add(s.delay).After(now)
		return !now.Before(c.notBefore()) && !(skipRetired && s.retiredCAs[c.ID]) && !waiting
	})
	var out []CA
	for _, i := range rotation.Candidates(entries, now, s.delay) {
		out = append(out, s.cas[index[i]])
	}
	return out
}

func (s *Set) judgeRetention(retention time.Duration, now time.Time) {
	entries, _ := s.entries(func(CA) bool { return true })
	valid := s.eligible(now, false)
	if len(valid) == 0 {
		return
	}
	active := slices.IndexFunc(s.cas, func(c CA) bool { return c.ID == valid[0].ID })
	for _, i := range rotation.Retired(entries, active, s.delay, retention, now) {
		s.retiredCAs[s.cas[i].ID] = true
	}
	// An anchor goes when every CA that chains to it has gone. One that no
	// CA here chains to, such as a root published ahead of its first
	// intermediate, stays.
	chained := map[string]bool{}
	alive := map[string]bool{}
	for _, c := range s.cas {
		id := certID(c.Anchor)
		chained[id] = true
		if !s.retiredCAs[c.ID] {
			alive[id] = true
		}
	}
	for id := range chained {
		if !alive[id] {
			s.retiredAnchors[id] = true
		}
	}
}

// CAs returns every CA, oldest first.
func (s *Set) CAs() []CA { return slices.Clone(s.cas) }

// Anchors returns the anchors to publish: all of them but those whose
// retention has ended.
func (s *Set) Anchors() []Anchor {
	var out []Anchor
	for _, a := range s.anchors {
		if !s.retiredAnchors[a.ID] {
			out = append(out, a)
		}
	}
	return out
}

// AllAnchors returns every anchor, retired ones included.
func (s *Set) AllAnchors() []Anchor { return slices.Clone(s.anchors) }

// AnchorRetired reports whether retention has ended for the anchor, so that
// it is no longer published.
func (s *Set) AnchorRetired(a Anchor) bool { return s.retiredAnchors[a.ID] }

// Retired returns the CAs whose retention has ended: nothing signed by them
// can still be valid, or be needed by a verifier. Their files can be pruned.
func (s *Set) Retired() []CA {
	var out []CA
	for _, c := range s.cas {
		if s.retiredCAs[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// AnchorIDs returns the IDs of the published anchors, sorted. Two sets
// publish the same anchors exactly when their IDs are equal.
func (s *Set) AnchorIDs() []string {
	var ids []string
	for _, a := range s.Anchors() {
		ids = append(ids, a.ID)
	}
	return ids
}

// Signing returns the CA that signs at now, ignoring how long its chain
// lasts: the newest one published for the activation delay. It reports false
// when no CA may sign, among them when the newest has expired: an older CA
// does not take over, because its anchor leaves the bundle once the newest
// has been active for the retention.
func (s *Set) Signing(now time.Time) (CA, bool) {
	c := s.candidates(now)
	if len(c) == 0 || !c[0].ValidAt(now) {
		return CA{}, false
	}
	return c[0], true
}

// SignsFrom returns when a CA, not signing yet, may start to.
func (s *Set) SignsFrom(c CA) time.Time { return s.effectivePublished(c).Add(s.delay) }

// Choice is the CA an X.509-SVID is to be signed by.
type Choice struct {
	CA CA
	// NotAfter is the latest notAfter the certificate may have: the earliest
	// of now plus the lifetime and the notAfter of the chain.
	NotAfter time.Time
	// Shortened is true when NotAfter is earlier than now plus the lifetime
	// because no CA's chain lasts that long. The issuer logs a warning.
	Shortened bool
}

// Select chooses the CA to sign an X.509-SVID of the given lifetime at now:
// the newest one that may sign, as SPEC section 2.5 says. It never falls back
// to an older CA because the newest one's chain is short: retention counts
// from the moment the newer CA activated, and what an older CA signed later
// could outlive its anchor in the bundle. The certificate ends with the chain
// when that comes before now plus the lifetime (Shortened). It fails with
// ErrNoSigningCA when no CA may sign, and with ErrExpiring when the chain
// leaves less than MinLifetime.
func (s *Set) Select(now time.Time, lifetime time.Duration) (Choice, error) {
	c, ok := s.Signing(now)
	if !ok {
		return Choice{}, ErrNoSigningCA
	}
	choice := Choice{CA: c, NotAfter: now.Add(lifetime).Truncate(time.Second)}
	if end := c.notAfter().Truncate(time.Second); end.Before(choice.NotAfter) {
		choice.NotAfter, choice.Shortened = end, true
	}
	if choice.NotAfter.Sub(now) < MinLifetime {
		return Choice{}, fmt.Errorf("%w: %s lasts until %s", ErrExpiring, c.File, c.notAfter().Format(time.RFC3339))
	}
	return choice, nil
}

// Usable reports whether the issuer can issue X.509-SVIDs of the given
// lifetime at now.
func (s *Set) Usable(now time.Time, lifetime time.Duration) bool {
	_, err := s.Select(now, lifetime)
	return err == nil
}

// WarnExpiry returns the CA that signs at now, if its chain ends within
// ExpiryWarning.
func (s *Set) WarnExpiry(now time.Time) []CA {
	var out []CA
	if c, ok := s.Signing(now); ok && c.notAfter().Sub(now) < ExpiryWarning {
		out = append(out, c)
	}
	return out
}
