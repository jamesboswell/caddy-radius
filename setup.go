package radiusauth

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
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
		radius.db, err = bolt.Open("radiusauth.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
		// create bucket
		radius.db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte("users"))
			if err != nil {
				return fmt.Errorf("create bucket: %s", err)
			}
			return nil
		})
		return radius
	})

	c.OnStartup(func() error {
		fmt.Println("***** CACHE PURGING *****")
		count, err := cachepurge(radius.db)
		if err != nil {
			fmt.Println("purge error ", err)
			return err
		}
		fmt.Printf("***** %d deleted\n", count)
		return nil
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
	securePaths := []string{}

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
				//TODO validate IP address & port number
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

			case "only":
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
					securePaths = append(securePaths, path)
				}

			case "cachetimeout":
				timeout := c.RemainingArgs()[0]
				t, err := strconv.Atoi(timeout)
				if err != nil {
					return config, c.Errf(`radiusauth: invalid timeout "%v" (must be an integer)`, timeout)
				}
				config.cachetimeout = time.Duration(t) * time.Second

			default:
				return config, c.Errf("radius: unknown property '%s'", c.Val())
			}
		}
	}

	if config.Server == "" || config.Secret == "" {
		return config, c.ArgErr()
	}

	if len(ignoredPaths) != 0 && len(securePaths) != 0 {
		return config, c.Errf("radiusauth: must use 'only' or 'except' path filters, but not both!")
	}
	if len(ignoredPaths) != 0 {
		config.requestFilter = &ignoredPathFilter{ignoredPaths: ignoredPaths}
	}
	if len(securePaths) != 0 {
		config.requestFilter = &securedPathFilter{securedPaths: securePaths}
	}

	return config, nil
}
