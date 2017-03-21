package radiusauth

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
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

	db, err := createCacheDB(configs.cache)
	if err != nil {
		return err
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		radius.Next = next
		radius.SiteRoot = root
		radius.Config = configs
		// radius.db, err = bolt.Open("/var/cache/radiusauth.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
		radius.db = db
		return radius
	})

	c.OnStartup(func() error {
		fmt.Println("***** [radiusauth] CACHE PURGING *****")
		count, err := cachePurge(radius.db)
		if err != nil {
			fmt.Println("purge error ", err)
			return err
		}
		fmt.Printf("***** [radiusauth] %d cache entries deleted\n", count)
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
				for _, server := range c.RemainingArgs() {

					host, port, err := net.SplitHostPort(server)
					if err != nil {
						return config, c.Errf("[radiusauth]: invalid server address %v", server)
					}
					//TODO validate IP address & port number
					config.Server = append(config.Server, net.JoinHostPort(host, port))
				}

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
						return config, c.Errf("[radiusauth]: ignore '/' entirely - disable [radiusauth] instead")
					}
					if !strings.HasPrefix(path, "/") {
						return config, c.Errf(`[radiusauth]: invalid path "%v" (must start with /)`, path)
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
						return config, c.Errf("[radiusauth]: ignore '/' entirely - disable [radiusauth] instead")
					}
					if !strings.HasPrefix(path, "/") {
						return config, c.Errf(`[radiusauth]: invalid path "%v" (must start with /)`, path)
					}
					securePaths = append(securePaths, path)
				}

			case "cache":
				fp := c.RemainingArgs()
				if len(fp) == 0 {
					return config, c.ArgErr()
				}
				config.cache = fp[0]

			case "cachetimeout":
				timeout := c.RemainingArgs()[0]
				t, err := strconv.Atoi(timeout)
				if err != nil {
					return config, c.Errf(`[radiusauth]: invalid timeout "%v" (must be an integer)`, timeout)
				}
				config.cachetimeout = time.Duration(t) * time.Second

			default:
				return config, c.Errf("[radiusauth]: unknown property '%s'", c.Val())
			}
		}
	}

	if len(config.Server) == 0 || config.Secret == "" {
		return config, c.ArgErr()
	}

	if len(ignoredPaths) != 0 && len(securePaths) != 0 {
		return config, c.Errf("[radiusauth]: must use 'only' or 'except' path filters, but not both!")
	}
	if len(ignoredPaths) != 0 {
		config.requestFilter = &ignoredPathFilter{ignoredPaths: ignoredPaths}
	}
	if len(securePaths) != 0 {
		config.requestFilter = &securedPathFilter{securedPaths: securePaths}
	}

	return config, nil
}

func createCacheDB(fp string) (*bolt.DB, error) {
	if !strings.HasSuffix(fp, "/") && runtime.GOOS != "windows" {
		fp = fp + "/"
	}
	fp = fp + "radiusauth.db"
	if isValidPath(fp) {
		b, err := bolt.Open(fp, 0600, &bolt.Options{Timeout: 1 * time.Second})
		// create bucket
		b.Update(func(tx *bolt.Tx) error {
			_, err2 := tx.CreateBucketIfNotExists([]byte("users"))
			if err2 != nil {
				return fmt.Errorf("create bucket: %s", err2)
			}
			return nil
		})
		return b, err
	}
	return nil, fmt.Errorf("Invalid path or permissions for cache %s", fp)
}

func isValidPath(fp string) bool {
	// Check if file already exists
	if _, err := os.Stat(fp); err == nil {
		return true
	}
	// Attempt to create it
	var d []byte
	if err := ioutil.WriteFile(fp, d, 0644); err == nil {
		os.Remove(fp) // And delete it
		return true
	}
	return false
}
