package issuer

import (
	"sync"
	"time"
)

// maxReplayEntriesPerClient caps how many unexpired assertions the cache
// holds for one client: about 50 a second over the longest assertion
// lifetime. Only assertions with a valid signature are recorded, so a client
// reaching the cap is misbehaving; it is then refused until entries expire,
// without affecting other clients.
const maxReplayEntriesPerClient = 1 << 14

// sweepInterval is how often expired entries are cleared out.
const sweepInterval = time.Minute

// replayCache remembers client assertion IDs until they expire, so each
// assertion is accepted once per issuer process.
type replayCache struct {
	mu        sync.Mutex
	clients   map[string]map[string]time.Time
	lastPrune map[string]time.Time
	lastSweep time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{clients: make(map[string]map[string]time.Time), lastPrune: make(map[string]time.Time)}
}

// use records jti for client until expires and reports whether it was unused
// and the client is under its cap.
func (c *replayCache) use(client, jti string, expires, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastSweep) >= sweepInterval {
		c.sweep(now)
		c.lastSweep = now
	}
	seen := c.clients[client]
	if seen == nil {
		seen = make(map[string]time.Time)
		c.clients[client] = seen
	}
	if until, ok := seen[jti]; ok && now.Before(until) {
		return false
	}
	if len(seen) >= maxReplayEntriesPerClient {
		// Pruning a full client costs a scan under the lock, so do it at
		// most once a second per client.
		if now.Sub(c.lastPrune[client]) < time.Second {
			return false
		}
		c.lastPrune[client] = now
		for id, until := range seen {
			if !now.Before(until) {
				delete(seen, id)
			}
		}
		if len(seen) >= maxReplayEntriesPerClient {
			return false
		}
	}
	seen[jti] = expires
	return true
}

func (c *replayCache) sweep(now time.Time) {
	for client, seen := range c.clients {
		for jti, expires := range seen {
			if !now.Before(expires) {
				delete(seen, jti)
			}
		}
		if len(seen) == 0 {
			delete(c.clients, client)
			delete(c.lastPrune, client)
		}
	}
}
