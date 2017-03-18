package radiusauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/boltdb/bolt"
	"github.com/jamesboswell/radius"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// RADIUS is the
type RADIUS struct {
	// Connection
	Next     httpserver.Handler
	SiteRoot string
	Config   radiusConfig
	db       *bolt.DB
}
type radiusConfig struct {
	Server        string
	Secret        string
	Timeout       int
	Retries       int
	nasid         string
	realm         string
	requestFilter filter
	cachetimeout  time.Duration
}

// ServeHTTP implements the httpserver.Handler interface.
func (a RADIUS) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	realm := "Basic realm=" + fmt.Sprintf("\"%s\"", a.Config.realm)
	// Pass-through when no paths match filter or no filters
	// if filter not nil and auth is NOT required, then just return
	if a.Config.requestFilter != nil && !a.Config.requestFilter.shouldAuthenticate(r) {
		return a.Next.ServeHTTP(w, r)
	}

	username, password, ok := r.BasicAuth()

	if !ok {
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}
	if username == "" || password == "" {
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, errors.New("[radiusauth] Blank username or password")
	}
	// cacheseek checks if provided Basic Auth credentials are cached and match
	// if credentials do not match cached entry, force RADIUS authentication
	cached, err := cacheseek(a, username, password)
	if cached == true && err == nil {
		fmt.Printf("CACHED:: %t, user: %s\n", cached, username)
		return a.Next.ServeHTTP(w, r)
	}
	if err != nil {
		fmt.Println(err)
	}

	// Provided credentials not found in cache or did not match
	// send username, password to RADIUS server for authentication

	isAuthenticated, err := auth(a, username, password)

	// if RADIUS authenticated, cache the username, password entry
	if isAuthenticated {
		fmt.Printf("Cache-write %s : %s\n", username, password)
		cachewrite(a, username, password)
	}

	// Handle auth errors
	if err != nil {
		// If Radius server timing out return 504 - StatusGatewayTimeout
		if isTimeout(err) {
			return http.StatusGatewayTimeout, err
		}
		// otherwise return 500 Internal Server Error
		return http.StatusInternalServerError, err
	}

	if !isAuthenticated {
		fmt.Println("Not authorized ", username) //TODO remove
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}

	return a.Next.ServeHTTP(w, r)
}

func auth(a RADIUS, username string, password string) (bool, error) {

	r := a.Config
	// Create a new RADIUS packet for Access-Request
	packet := radius.New(radius.CodeAccessRequest, []byte(r.Secret))
	packet.Add("User-Name", username)
	packet.Add("User-Password", password)
	packet.Add("NAS-Identifier", r.nasid)

	client := radius.Client{
		DialTimeout: 3 * time.Second, // TODO user defined timeouts
		ReadTimeout: 3 * time.Second,
	}

	hostport := r.Server
	received, err := client.Exchange(packet, hostport)
	fmt.Println("****RADIUS server called: ", hostport)
	if err != nil {
		if isTimeout(err) {
			return false, err
		}
		//TODO handle other errors?
		return false, err
	}

	// RADIUS Access-Accept is a successful authentication
	if received.Code == radius.CodeAccessAccept {
		return true, nil
	}
	return false, nil
}

// isTimeout checks for net timeout
func isTimeout(err error) bool {
	if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
		return true
	}
	return false
}
