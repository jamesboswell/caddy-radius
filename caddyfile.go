package radiusauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// parseCaddyfile unmarshals a radiusauth Caddyfile directive into a RadiusAuth.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	ra := new(RadiusAuth)
	return ra, ra.UnmarshalCaddyfile(h.Dispenser)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	radiusauth {
//	    server   host:port [host:port ...]
//	    secret   sharedsecret
//	    realm    "My Realm"
//	    nas_id   mynas
//	    cache    /var/lib/caddy
//	    cache_timeout 5m
//	    except   /public /assets
//	    only     /admin /api
//	}
func (ra *RadiusAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "server":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				ra.Servers = append(ra.Servers, args...)

			case "secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ra.Secret = d.Val()

			case "realm":
				ra.Realm = strings.Join(d.RemainingArgs(), " ")

			case "nas_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ra.NASID = d.Val()

			case "cache":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ra.CachePath = d.Val()

			case "cache_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t, err := time.ParseDuration(d.Val())
				if err != nil {
					// accept plain integer as seconds for backwards compat
					var secs int
					if _, serr := fmt.Sscanf(d.Val(), "%d", &secs); serr != nil {
						return d.Errf("invalid cache_timeout %q: %v", d.Val(), err)
					}
					t = time.Duration(secs) * time.Second
				}
				ra.CacheTimeout = caddy.Duration(t)

			case "except":
				paths := d.RemainingArgs()
				if len(paths) == 0 {
					return d.ArgErr()
				}
				ra.ExceptPaths = append(ra.ExceptPaths, paths...)

			case "only":
				paths := d.RemainingArgs()
				if len(paths) == 0 {
					return d.ArgErr()
				}
				ra.OnlyPaths = append(ra.OnlyPaths, paths...)

			default:
				return d.Errf("unknown radiusauth option: %s", d.Val())
			}
		}
	}
	return nil
}
