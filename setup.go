package radiusauth

import (
	"net"
	"os"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("radiusauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	root := cfg.Root
	configs, err := parseRadiusConfig(c)
	if err != nil {
		return err
	}

	radius := RADIUS{}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		radius.Next = next
		radius.SiteRoot = root
		radius.Config = configs
		return radius
	})
	return nil
}

// parseRadiusConfig parses the Caddy directive
func parseRadiusConfig(c *caddy.Controller) (radiusConfig, error) {
	config := radiusConfig{}

	// Set RADIUS NAS-Identifier
	nasid, err := os.Hostname()
	if err != nil {
		config.nasid = "caddy-server"
	}
	config.nasid = nasid

	ignoredPaths := []string{}

	for c.Next() {
		// No extra args expected
		if len(c.RemainingArgs()) > 0 {
			return config, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "server":
				server := c.RemainingArgs()[0]
				// spew.Dump(server)

				host, port, err := net.SplitHostPort(server)
				if err != nil {
					return config, c.Errf("radius: invalid server address %v", server)
				}
				config.Server = net.JoinHostPort(host, port)
			case "secret":
				config.Secret = c.RemainingArgs()[0]

			case "realm":
				var realm string
				for _, a := range c.RemainingArgs() {
					realm = realm + a
				}
				config.realm = realm

			case "except":
				paths := c.RemainingArgs()
				if len(paths) == 0 {
					return config, c.ArgErr()
				}
				for _, path := range paths {
					if path == "/" {
						return config, c.Errf("ldap: ignore '/' entirely - disable ldap instead")
					}
					if !strings.HasPrefix(path, "/") {
						return config, c.Errf(`radiusauth: invalid path "%v" (must start with /)`, path)
					}
					ignoredPaths = append(ignoredPaths, path)
				}

			default:
				return config, c.Errf("radius: unknown property '%s'", c.Val())
			}
		}
	}

	if config.Server == "" || config.Secret == "" {
		return config, c.ArgErr()
	}

	if len(ignoredPaths) != 0 {
		config.requestFilter = &ignoredPathFilter{ignoredPaths: ignoredPaths}
	}

	return config, nil
}
