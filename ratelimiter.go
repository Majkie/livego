package livego

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	var recent []time.Time
	for _, t := range rl.requests[identifier] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		return false
	}

	recent = append(recent, now)
	rl.requests[identifier] = recent
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-rl.window)

		var keysToDelete []string
		updatedEntries := make(map[string][]time.Time)

		rl.mu.Lock()
		for key, times := range rl.requests {
			var recent []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				keysToDelete = append(keysToDelete, key)
			} else {
				updatedEntries[key] = recent
			}
		}

		for _, key := range keysToDelete {
			delete(rl.requests, key)
		}
		for key, recent := range updatedEntries {
			rl.requests[key] = recent
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		userAgent := r.UserAgent()

		if len(userAgent) > 200 {
			userAgent = userAgent[:200]
		}

		identifier := clientIP + "|" + userAgent

		if !rl.Allow(identifier) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
			w.Header().Set("X-RateLimit-Window", rl.window.String())
			writeRateLimitError(w, "Rate limit exceeded", map[string]interface{}{
				"limit":      rl.limit,
				"window":     rl.window.String(),
				"identifier": clientIP,
			})
			return
		}

		next(w, r)
	}
}
