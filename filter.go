package radiusauth

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
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
	for _, securedPath := range s.securedPaths {
		if httpserver.Path(r.URL.Path).Matches(securedPath) {
			return true
		}
	}
	return false
}

func (i *ignoredPathFilter) shouldAuthenticate(r *http.Request) bool {
	for _, ignoredPath := range i.ignoredPaths {
		if httpserver.Path(r.URL.Path).Matches(ignoredPath) {
			return false
		}
	}
	return true
}
