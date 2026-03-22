package radiusauth

// Rate limiting protects RADIUS infrastructure from brute-force attacks.
//
// RADIUS servers are shared authentication backends. Without rate limiting,
// an attacker can make unlimited authentication attempts through this module,
// both brute-forcing credentials and overwhelming the RADIUS server(s).
//
// This in-memory rate limiter blocks repeat offenders before any RADIUS
// packet is sent, protecting both credentials and backend infrastructure.
// The max_failures and failure_window fields are mandatory in the Caddyfile
// to ensure operators cannot accidentally deploy without brute-force protection.

import (
	"net"
	"sync"
	"time"
)

// failRecord tracks failed authentication attempts from a single IP.
type failRecord struct {
	count       int
	windowStart time.Time
}

// rateLimiter tracks per-IP authentication failures.
//
// This is allocated as a pointer field in RadiusAuth so that the
// value-receiver ServeHTTP (which copies the RadiusAuth struct on
// every request) still shares the same map and mutex. If this field
// is ever changed from a pointer to a value, rate limiting will
// silently break — every request would get its own empty map.
type rateLimiter struct {
	mu       sync.Mutex
	failures map[string]*failRecord
	stop     chan struct{}
}

// isBlocked returns true if the given IP has exceeded maxFailures
// within the current window.
func (rl *rateLimiter) isBlocked(ip string, maxFailures int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.failures[ip]
	if !ok {
		return false
	}
	if time.Since(rec.windowStart) > window {
		delete(rl.failures, ip)
		return false
	}
	return rec.count >= maxFailures
}

// recordFailure increments the failure count for the given IP.
// If the existing window has expired, a new window is started.
func (rl *rateLimiter) recordFailure(ip string, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.failures[ip]
	if !ok || time.Since(rec.windowStart) > window {
		rl.failures[ip] = &failRecord{count: 1, windowStart: time.Now()}
		return
	}
	rec.count++
}

// clearFailures removes the failure record for an IP after a
// successful authentication, resetting their counter to zero.
func (rl *rateLimiter) clearFailures(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, ip)
}

// cleanupLoop periodically removes expired entries from the failure map
// to prevent unbounded memory growth from long-gone attackers.
func (rl *rateLimiter) cleanupLoop(window time.Duration) {
	ticker := time.NewTicker(window)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, rec := range rl.failures {
				if now.Sub(rec.windowStart) > window {
					delete(rl.failures, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

// extractIP returns the IP portion of a RemoteAddr string,
// stripping the port. Handles IPv4 ("1.2.3.4:8080"),
// IPv6 ("[::1]:8080"), and bare addresses ("1.2.3.4").
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
