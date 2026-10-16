package manage

import (
	"container/list"
	"sync"
	"time"
)

// maxCallers bounds how many callers the limiter tracks. When that many are
// tracked, the one heard from longest ago is forgotten to make room.
const maxCallers = 1 << 16

// callerLimiter is a token bucket per caller, keyed by SPIFFE ID.
type callerLimiter struct {
	perSecond float64
	burst     float64

	mu      sync.Mutex
	buckets map[string]*list.Element
	// recent orders the buckets by last use, most recent first.
	recent *list.List
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

func newCallerLimiter(perSecond, burst float64) *callerLimiter {
	return &callerLimiter{perSecond: perSecond, burst: burst, buckets: map[string]*list.Element{}, recent: list.New()}
}

func (l *callerLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.buckets[key]
	if e == nil {
		if l.recent.Len() >= maxCallers {
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
