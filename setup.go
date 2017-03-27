package radiusauth

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	// Must have a server and secret
	if len(config.Server) == 0 || config.Secret == "" {
		return config, c.Errf("[radiusauth]: server or secret undefined")
	}

	if len(ignoredPaths) != 0 && len(securePaths) != 0 {
		return config, c.Errf("[radiusauth]: must use 'only' OR 'except' path filters, but not both!")
	}
	if len(ignoredPaths) != 0 {
		config.requestFilter = &ignoredPathFilter{ignoredPaths: ignoredPaths}
	}
	if len(securePaths) != 0 {
		config.requestFilter = &securedPathFilter{securedPaths: securePaths}
	}

	return config, nil
}

// createCacheDB creates a BoltDB database in fp file path
// will return err if file cannot be created or bucket cannot be created
func createCacheDB(fp string) (*bolt.DB, error) {
	fp = filepath.Join(fp, "radiusauth.db")
	// Open or create BoltDB if not exists
	// set file readable only by Caddy process owner
	// set file lock timeout to 1 sec
	b, err := bolt.Open(fp, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	// create "users" bucket to store logins
	err = b.Update(func(tx *bolt.Tx) error {
		_, err2 := tx.CreateBucketIfNotExists([]byte("users"))
		if err2 != nil {
			return fmt.Errorf("create bucket: %s", err2)
		}
		return nil
	})
	return b, err
}
