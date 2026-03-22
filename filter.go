package radiusauth

import (
	"net/http"
	"strings"
)

type filter interface {
	shouldAuthenticate(r *http.Request) bool
}

type securedPathFilter struct {
	securedPaths []string
}

type ignoredPathFilter struct {
	ignoredPaths []string
}

func (s *securedPathFilter) shouldAuthenticate(r *http.Request) bool {
	for _, p := range s.securedPaths {
		if pathMatches(r.URL.Path, p) {
			return true
		}
	}
	return false
}

func (i *ignoredPathFilter) shouldAuthenticate(r *http.Request) bool {
	for _, p := range i.ignoredPaths {
		if pathMatches(r.URL.Path, p) {
			return false
		}
	}
	return true
}

// pathMatches reports whether requestPath falls under prefix in a
// path-segment-aware way. "/admin" matches "/admin" and "/admin/panel"
// but not "/administrator".
func pathMatches(requestPath, prefix string) bool {
	if !strings.HasPrefix(requestPath, prefix) {
		return false
	}
	// Exact match or the next character is a slash (segment boundary).
	return len(requestPath) == len(prefix) || requestPath[len(prefix)] == '/'
}
