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
		if strings.HasPrefix(r.URL.Path, p) {
			return true
		}
	}
	return false
}

func (i *ignoredPathFilter) shouldAuthenticate(r *http.Request) bool {
	for _, p := range i.ignoredPaths {
		if strings.HasPrefix(r.URL.Path, p) {
			return false
		}
	}
	return true
}
