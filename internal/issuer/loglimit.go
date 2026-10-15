package issuer

import (
	"sync"
	"time"
)

// logLimiter allows a burst of log lines and then one a second.
type logLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

const logBurst = 10

func (l *logLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.tokens = logBurst
	} else {
		l.tokens = min(logBurst, l.tokens+now.Sub(l.last).Seconds())
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
