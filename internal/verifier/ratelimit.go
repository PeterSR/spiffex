package verifier

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// maxAddresses bounds how many client addresses the limiter tracks. When
// that many are tracked, the one used longest ago is forgotten to make room.
const maxAddresses = 1 << 16

// addressLimiter is a token bucket per client address. IPv6 clients are
// grouped by their /64, which one host usually has to itself, so that
// moving between its addresses gains nothing.
type addressLimiter struct {
	perSecond float64
	burst     float64

	mu      sync.Mutex
	buckets map[netip.Addr]*list.Element
	// recent orders the buckets by last use, most recent first.
	recent *list.List
}

type bucket struct {
	key    netip.Addr
	tokens float64
	last   time.Time
}

func newAddressLimiter(perSecond, burst float64) *addressLimiter {
	return &addressLimiter{perSecond: perSecond, burst: burst, buckets: map[netip.Addr]*list.Element{}, recent: list.New()}
}

func clientKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return addr
}

func (l *addressLimiter) allow(addr netip.Addr, now time.Time) bool {
	key := clientKey(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.buckets[key]
	if e == nil {
		if l.recent.Len() >= maxAddresses {
			oldest := l.recent.Back()
			delete(l.buckets, oldest.Value.(*bucket).key)
			l.recent.Remove(oldest)
		}
		e = l.recent.PushFront(&bucket{key: key, tokens: l.burst, last: now})
		l.buckets[key] = e
	}
	l.recent.MoveToFront(e)
	b := e.Value.(*bucket)
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSecond)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
