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

// siteFactor is how many times the rate and burst of one address a whole
// IPv6 /48 gets.
const siteFactor = 16

// addressLimiter is a token bucket per client address. IPv6 clients are
// grouped by their /64, which one host usually has to itself, so that
// moving between its addresses gains nothing; and their /48, a site's
// usual allocation, has a bucket of its own, siteFactor times as large, so
// that moving between /64s gains little more.
type addressLimiter struct {
	perSecond float64
	burst     float64

	mu      sync.Mutex
	buckets map[netip.Prefix]*list.Element
	// recent orders the buckets by last use, most recent first.
	recent *list.List
}

type bucket struct {
	key    netip.Prefix
	tokens float64
	last   time.Time
}

func newAddressLimiter(perSecond, burst float64) *addressLimiter {
	return &addressLimiter{perSecond: perSecond, burst: burst, buckets: map[netip.Prefix]*list.Element{}, recent: list.New()}
}

// clientKeys are the buckets a start from addr draws on, each with how
// many times the single address's rate and burst it has.
func clientKeys(addr netip.Addr) ([]netip.Prefix, []float64) {
	addr = addr.Unmap()
	if !addr.Is6() {
		return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, []float64{1}
	}
	host, _ := addr.Prefix(64)
	site, _ := addr.Prefix(48)
	return []netip.Prefix{host, site}, []float64{1, siteFactor}
}

// allow takes a token from each of the address's buckets, or from none
// when any of them is empty.
func (l *addressLimiter) allow(addr netip.Addr, now time.Time) bool {
	keys, factors := clientKeys(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	buckets := make([]*bucket, len(keys))
	ok := true
	for i, key := range keys {
		b := l.bucket(key, factors[i], now)
		b.tokens = min(l.burst*factors[i], b.tokens+now.Sub(b.last).Seconds()*l.perSecond*factors[i])
		b.last = now
		buckets[i] = b
		ok = ok && b.tokens >= 1
	}
	if !ok {
		return false
	}
	for _, b := range buckets {
		b.tokens--
	}
	return true
}

func (l *addressLimiter) bucket(key netip.Prefix, factor float64, now time.Time) *bucket {
	e := l.buckets[key]
	if e == nil {
		if l.recent.Len() >= maxAddresses {
			oldest := l.recent.Back()
			delete(l.buckets, oldest.Value.(*bucket).key)
			l.recent.Remove(oldest)
		}
		e = l.recent.PushFront(&bucket{key: key, tokens: l.burst * factor, last: now})
		l.buckets[key] = e
	}
	l.recent.MoveToFront(e)
	return e.Value.(*bucket)
}
