package radiusauth

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jamesboswell/radius"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// RADIUS is the
type RADIUS struct {
	// Connectino
	Next     httpserver.Handler
	SiteRoot string
	Config   radiusConfig
}
type radiusConfig struct {
	Server        string
	Secret        string
	Timeout       int
	Retries       int
	nasid         string
	realm         string
	requestFilter filter
}

// ServeHTTP implements the httpserver.Handler interface.
func (a RADIUS) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	realm := "Basic realm=" + fmt.Sprintf("\"%s\"", a.Config.realm)
	// Pass-through when no paths match

	// spew.Dump(a.Config.requestFilter)

	// if filter not nil and auth is NOT required, then just return
	// 'except'
	if a.Config.requestFilter != nil && !a.Config.requestFilter.shouldAuthenticate(r) {
		return a.Next.ServeHTTP(w, r)
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		fmt.Println("Not OK authorized ", username)
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}

	isAuthenticated, err := auth(a.Config, username, password)

	// If Radius server timing out return 504 - StatusGatewayTimeout
	if isTimeout(err) {
		w.WriteHeader(http.StatusGatewayTimeout)
		return http.StatusGatewayTimeout, err
	}

	if !isAuthenticated {
		fmt.Println("Not authorized ", username) //TODO remove
		w.Header().Set("WWW-Authenticate", realm)
		return http.StatusUnauthorized, nil
	}

	return a.Next.ServeHTTP(w, r)
}

func auth(r radiusConfig, username string, password string) (bool, error) {

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
	if err != nil {
		if isTimeout(err) {
			return false, err
		}
		//TODO handle other errors?
		return false, err
	}

	// status := "Reject"
	if received.Code == radius.CodeAccessAccept {
		// status = "Accept"
		return true, nil
	}
	// fmt.Println(status)
	return false, nil
}

// isTimeout checks for net timeout
func isTimeout(err error) bool {
	if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
		return true
	}
	return false
}
