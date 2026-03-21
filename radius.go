// Package radiusauth provides HTTP Basic Authentication for Caddy v2 against
// RFC2865 RADIUS servers.
//
// Uses standard HTTP Basic Authentication headers with credential authentication
// performed by a RADIUS server. Optional path filtering [except|only] allows
// toggling authentication on a per-path basis. A local BoltDB cache reduces
// repeat RADIUS calls.
package radiusauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
	"github.com/jamesboswell/radius"
	"github.com/jamesboswell/radius/rfc2865"
)

func init() {
	caddy.RegisterModule(RadiusAuth{})
	httpcaddyfile.RegisterHandlerDirective("radiusauth", parseCaddyfile)
}

// RadiusAuth implements HTTP Basic Authentication against a RADIUS server.
type RadiusAuth struct {
	// RADIUS server addresses in host:port format. Multiple servers provide failover.
	Servers []string `json:"servers"`

	// Shared secret for RADIUS communication.
	Secret string `json:"secret"`

	// Realm for the WWW-Authenticate header. Defaults to "Restricted".
	Realm string `json:"realm,omitempty"`

	// NAS-Identifier attribute sent in Access-Request. Defaults to system hostname.
	NASID string `json:"nas_id,omitempty"`

	// How long to cache successful authentications (e.g. "5m"). 0 disables caching.
	CacheTimeout caddy.Duration `json:"cache_timeout,omitempty"`

	// Directory to store the BoltDB cache file. Required when cache_timeout > 0.
	CachePath string `json:"cache_path,omitempty"`

	// Paths to exclude from authentication. Cannot be combined with OnlyPaths.
	ExceptPaths []string `json:"except,omitempty"`

	// Paths to require authentication on. Cannot be combined with ExceptPaths.
	OnlyPaths []string `json:"only,omitempty"`

	db            *bolt.DB
	requestFilter filter
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (RadiusAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.radiusauth",
		New: func() caddy.Module { return new(RadiusAuth) },
	}
}

// Provision sets up the RadiusAuth middleware.
func (ra *RadiusAuth) Provision(ctx caddy.Context) error {
	ra.logger = ctx.Logger()

	if ra.Realm == "" {
		ra.Realm = "Restricted"
	}

	if ra.NASID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			ra.NASID = "caddy-server"
		} else {
			ra.NASID = hostname
		}
	}

	if len(ra.ExceptPaths) > 0 {
		ra.requestFilter = &ignoredPathFilter{ignoredPaths: ra.ExceptPaths}
	} else if len(ra.OnlyPaths) > 0 {
		ra.requestFilter = &securedPathFilter{securedPaths: ra.OnlyPaths}
	}

	if ra.CacheTimeout > 0 {
		if ra.CachePath == "" {
			return errors.New("cache_path is required when cache_timeout > 0")
		}
		db, err := openCacheDB(ra.CachePath)
		if err != nil {
			return fmt.Errorf("opening cache db: %v", err)
		}
		ra.db = db

		count, err := cachePurge(ra.db, time.Duration(ra.CacheTimeout))
		if err != nil {
			ra.logger.Warn("cache purge on startup failed", zap.Error(err))
		} else {
			ra.logger.Info("cache purged stale entries on startup", zap.Int("count", count))
		}
	}

	return nil
}

// Validate validates the RadiusAuth configuration.
func (ra *RadiusAuth) Validate() error {
	if len(ra.Servers) == 0 {
		return errors.New("at least one RADIUS server is required")
	}
	for _, s := range ra.Servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return fmt.Errorf("invalid server address %q: %v", s, err)
		}
	}
	if ra.Secret == "" {
		return errors.New("RADIUS shared secret is required")
	}
	if len(ra.ExceptPaths) > 0 && len(ra.OnlyPaths) > 0 {
		return errors.New("cannot use both 'except' and 'only' path filters")
	}
	return nil
}

// Cleanup closes the BoltDB connection when the module is unloaded.
func (ra *RadiusAuth) Cleanup() error {
	if ra.db != nil {
		return ra.db.Close()
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (ra RadiusAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if ra.requestFilter != nil && !ra.requestFilter.shouldAuthenticate(r) {
		return next.ServeHTTP(w, r)
	}

	username, password, ok := r.BasicAuth()
	realm := `Basic realm="` + ra.Realm + `"`

	if !ok || username == "" || password == "" {
		w.Header().Set("WWW-Authenticate", realm)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}

	// Check credential cache before hitting RADIUS
	if ra.db != nil && ra.CacheTimeout > 0 {
		cached, err := cacheSeek(ra, username, password)
		if cached {
			ra.logger.Debug("cache hit", zap.String("user", username))
			return next.ServeHTTP(w, r)
		}
		if err != nil {
			ra.logger.Debug("cache miss", zap.String("user", username), zap.Error(err))
		}
	}

	authenticated, err := ra.radiusAuth(username, password)
	if err != nil {
		return fmt.Errorf("[radiusauth] all RADIUS servers failed: %v", err)
	}

	if !authenticated {
		w.Header().Set("WWW-Authenticate", realm)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}

	if ra.db != nil && ra.CacheTimeout > 0 {
		if err := cacheWrite(ra, username, password); err != nil {
			ra.logger.Warn("cache write failed", zap.String("user", username), zap.Error(err))
		}
	}

	return next.ServeHTTP(w, r)
}

// radiusAuth sends an Access-Request to each configured RADIUS server in order,
// returning true on Accept, false on Reject, or an error if all servers fail.
func (ra RadiusAuth) radiusAuth(username, password string) (bool, error) {
	packet := radius.New(radius.CodeAccessRequest, []byte(ra.Secret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	rfc2865.NASIdentifier_SetString(packet, ra.NASID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lastErr error
	for _, server := range ra.Servers {
		reply, err := radius.Exchange(ctx, packet, server)
		if err != nil {
			ra.logger.Warn("RADIUS server unreachable", zap.String("server", server), zap.Error(err))
			lastErr = err
			continue
		}
		switch reply.Code {
		case radius.CodeAccessAccept:
			return true, nil
		case radius.CodeAccessReject:
			return false, nil
		default:
			ra.logger.Warn("unexpected RADIUS response code",
				zap.String("server", server),
				zap.Stringer("code", reply.Code),
			)
		}
	}
	return false, fmt.Errorf("all servers unreachable: %v", lastErr)
}

// Interface guards — compilation fails if RadiusAuth stops satisfying these.
var (
	_ caddy.Module                = (*RadiusAuth)(nil)
	_ caddy.Provisioner           = (*RadiusAuth)(nil)
	_ caddy.Validator             = (*RadiusAuth)(nil)
	_ caddy.CleanerUpper          = (*RadiusAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*RadiusAuth)(nil)
	_ caddyfile.Unmarshaler       = (*RadiusAuth)(nil)
)
