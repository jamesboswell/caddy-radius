// Package radiusauth provides HTTP Basic Authentication for Caddy against
// RFC2865 RADIUS Servers
//
// Uses standard HTTP Basic Authentication authorization headers with user
// credential authentication performed by a RADIUS server. Path filtering
// [except|only] allows toggling authentication on a per path basis.
//
// A local authentication cache is utilized to reduce repeat RADIUS calls.
package radiusauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/boltdb/bolt"
	"github.com/jamesboswell/radius"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// RADIUS is middleware to protect resources with a username and password.
// HTTP Basic Authentication is performed with username and password being
// authenticated against a RADIUS server. Local caching is performed to reduce
// the number of RADIUS calls
//
// Note that HTTP Basic Authentication is not secure by itself and should
// not be used to protect important assets without HTTPS. Even then, the
// security of HTTP Basic Auth is disputed. Use discretion when deciding
// what to protect with BasicAuth.
type RADIUS struct {
	// Connection
	Next     httpserver.Handler
	SiteRoot string
	Config   radiusConfig
	db       *bolt.DB
}
type radiusConfig struct {
	Server        []string
	Secret        string
	Timeout       int
	Retries       int
	nasid         string
	realm         string
	requestFilter filter
	cache         string
	cachetimeout  time.Duration
}

// ServeHTTP implements the httpserver.Handler interface.
func (a RADIUS) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// Pass-through when no paths match filter or no filters
	// if filter not nil and auth is NOT required, then just return
	if a.Config.requestFilter != nil && !a.Config.requestFilter.shouldAuthenticate(r) {
		return a.Next.ServeHTTP(w, r)
	}

	// Check for HTTP Basic Authorization Headers and valid username, password
	username, password, ok := r.BasicAuth()

	realm := "Basic realm=" + fmt.Sprintf("\"%s\"", a.Config.realm)
	if !ok {
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}
	if username == "" || password == "" {
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, errors.New("[radiusauth] Blank username or password")
	}

	// Capture username into {user} placeholder for caddyfile log directive
	// ex:  log / stdout "{remote} - {user} [{when}] {method} {uri} {proto} {status} {size}"
	*r = *r.WithContext(context.WithValue(r.Context(),
		httpserver.RemoteUserCtxKey, username))

	// cacheseek checks if provided Basic Auth credentials are cached and match
	// if credentials do not match cached entry, force RADIUS authentication
	isCached, err := cacheSeek(a, username, password)
	if isCached == true && err == nil {
		return a.Next.ServeHTTP(w, r)
	}
	if err != nil {
		fmt.Println(err)
	}

	// send username, password to RADIUS server(s) for authentication
	// returns isAuthenticated if authentication successful
	// err if no RADIUS servers respond
	isAuthenticated, err := auth(a.Config, username, password)

	// Return 500 Internal Server Error
	// if connection to all RADIUS servers has failed
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// if RADIUS authentication failed, return 401
	if !isAuthenticated {
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}
	// if RADIUS authenticated, cache the username, password entry return Handler
	if isAuthenticated {
		if err := cacheWrite(a, username, password); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("[radiusauth] cache-write for %s FAILED: %s", username, err)
		}
	}
	return a.Next.ServeHTTP(w, r)
}

// auth generates a RADIUS authentication request for username
func auth(r radiusConfig, username string, password string) (bool, error) {
	// Create a new RADIUS packet for Access-Request
	// NAS-Identifier required by some servers such as CiscoSecure ACS
	packet := radius.New(radius.CodeAccessRequest, []byte(r.Secret))
	packet.Add("User-Name", username)
	packet.Add("User-Password", password)
	packet.Add("NAS-Identifier", r.nasid)

	client := radius.Client{
		DialTimeout: 3 * time.Second, // TODO user defined timeouts
		ReadTimeout: 3 * time.Second,
	}

	for s, radiusServer := range r.Server {
		reply, err := client.Exchange(packet, radiusServer)
		if err != nil {
			// Return err if all servers in pool have failed
			if s == len(r.Server)-1 {
				return false, fmt.Errorf("[radiusauth] All RADIUS servers failed %s", err)
			}
			//TODO handle other errors?
			// TODO need a way to hook into Caddy error log
			// without a return here as we want to finish loop
			// to try all configured servers
			fmt.Println(err)
			continue
		}
		// RADIUS Access-Accept is a successful authentication
		if reply.Code == radius.CodeAccessAccept {
			return true, nil
		}
	}
	// Any other reply is a failed authentication
	return false, nil
}
