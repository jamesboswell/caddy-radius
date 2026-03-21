# caddy-radius

[![Go Reference](https://pkg.go.dev/badge/github.com/jamesboswell/caddy-radius.svg)](https://pkg.go.dev/github.com/jamesboswell/caddy-radius)


caddy-radius is a [Caddy v2](https://caddyserver.com/) plugin that provides HTTP Basic Authentication using a [RADIUS](https://en.wikipedia.org/wiki/RADIUS) server.

When a browser requests a protected resource, it prompts for credentials. Those credentials are sent to a configured RADIUS server. On `Access-Accept` the request is forwarded; on `Access-Reject` a `401 Unauthorized` is returned.

> **Security note:** RADIUS uses MD5-based packet authentication. The link between Caddy and the RADIUS server should be on a trusted network, or secured separately (e.g. IPsec).

Successful authentications are cached in a local BoltDB file to reduce repeat RADIUS round-trips. Subsequent requests check the cache first; only a cache miss or an expired entry causes a new RADIUS exchange.

### Authentication flow

```
+------------+    +---------------+    +------------+    +--------+
|HTTP request|--->| secured path? |--->|  cached?   |--->| RADIUS |
+------------+    +-------+-------+    +-----+------+    +---+----+
                          |no               |yes              |Accept
                          v                 v                 v
                    +----------+      +----------+      +----------+
                    |  Grant   |      |  Grant   |      |  Grant   |
                    |  Access  |      |  Access  |      |  Access  |
                    +----------+      +----------+      +----------+
                                                             |Reject
                                                             v
                                                       +----------+
                                                       | 401      |
                                                       | Unauth.  |
                                                       +----------+
```

## Installation

Use [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/jamesboswell/caddy-radius
```

## Caddyfile syntax

```caddyfile
{
    order radiusauth before respond
}

example.com {
    radiusauth {
        server  192.0.2.10:1812 192.0.2.90:1812
        secret  SuperSecretSharedSecret
        realm   "ACME Corp"
        except  /public /assets /health
        cache   /var/lib/caddy
        cache_timeout 5m
    }

    respond "Hello, world!" 200
}
```

### Directive options

| Option | Description |
|---|---|
| `server` | One or more RADIUS server addresses in `host:port` format. Tried in order; first response wins. |
| `secret` | RADIUS shared secret. |
| `realm` | Value for the `WWW-Authenticate: Basic realm=` header. Default: `Restricted`. |
| `nas_id` | RADIUS `NAS-Identifier` attribute. Default: system hostname. |
| `except` | Space-separated path prefixes to **exclude** from authentication. Cannot be combined with `only`. |
| `only` | Space-separated path prefixes to **require** authentication on. Cannot be combined with `except`. |
| `cache` | Directory for the BoltDB credential cache file (`radiusauth.db`). Required when `cache_timeout > 0`. |
| `cache_timeout` | How long to cache a successful authentication. Accepts Go duration strings (`5m`, `1h`) or plain integer seconds for backwards compatibility. `0` disables caching. |

## JSON config

```json
{
  "handler": "radiusauth",
  "servers": ["192.0.2.10:1812", "192.0.2.90:1812"],
  "secret": "SuperSecretSharedSecret",
  "realm": "ACME Corp",
  "except": ["/public", "/assets", "/health"],
  "cache_path": "/var/lib/caddy",
  "cache_timeout": 300000000000
}
```

(`cache_timeout` is in nanoseconds in JSON — `300000000000` = 5 minutes.)

## Tested against

- FreeRADIUS 3.x
- CiscoSecure ACS 5.4

## DISCLAIMER

This software is provided as-is. No warranties or claims of quality or security are made. Perform your own security analysis and accept the risks accordingly.
