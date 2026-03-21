# caddy-radius Modernization Worklog

## Goal
Modernize `github.com/jamesboswell/caddy-radius` from Caddy v1 (circa 2017) to Caddy v2,
updating all dependencies and rewriting the plugin to use the Caddy v2 module system.

---

## Session 1 — 2026-03-21

### Branch
All work is on branch: `caddy-v2`
Master is untouched as a v1 historical reference.

---

### Completed

#### Phase 1 — Workspace setup ✅
- Cloned repo to `/Users/jboswell/workspace/caddy-radius`
- Initialized `go.mod` (`module github.com/jamesboswell/caddy-radius`, go 1.26.1)
- Committed: `Initialize go.mod and migrate BoltDB to go.etcd.io/bbolt`

#### Phase 2 — BoltDB → bbolt ✅
- Replaced `github.com/boltdb/bolt` with `go.etcd.io/bbolt` in `cache.go`, `radius.go`, `setup.go`
- Used import alias `bolt "go.etcd.io/bbolt"` — zero logic changes, drop-in replacement
- Committed as part of Phase 1 commit

#### Phase 3 — Dependency decisions ✅
- **RADIUS library**: Use `github.com/jamesboswell/radius` (author's own fork, updated to use correct module path)
- **Cache**: Keep file-based BoltDB (bbolt) — user preference over in-memory

#### Phase 4 — Caddy v2 rewrite ✅ (code written, build not yet verified)

Files rewritten:

**`radius.go`** — Full rewrite. Now contains:
- `RadiusAuth` struct with JSON-tagged config fields
- `CaddyModule()` → module ID `http.handlers.radiusauth`
- `Provision(ctx caddy.Context)` — sets up logger, path filter, opens bbolt DB, purges stale cache
- `Validate()` — checks servers, secret, port formats, filter conflicts
- `Cleanup()` — closes bbolt DB on module unload
- `ServeHTTP(w, r, next caddyhttp.Handler)` — v2 middleware signature
- `radiusAuth()` — RADIUS exchange using `github.com/jamesboswell/radius` + `rfc2865`
- `UnmarshalCaddyfile()` — parses `radiusauth { }` block
- `parseCaddyfile()` — `httpcaddyfile.RegisterHandlerDirective` handler
- `init()` — registers module and Caddyfile directive
- Interface guards for all implemented interfaces

**`cache.go`** — Rewritten:
- Import updated to `go.etcd.io/bbolt`
- Struct references changed from `RADIUS` → `RadiusAuth`
- `r.Config.cachetimeout` → `time.Duration(ra.CacheTimeout)`
- `cachePurge` now accepts `timeout time.Duration` param (was hardcoded 10min)
- `openCacheDB()` replaces `createCacheDB()`
- Cleaner error handling throughout

**`filter.go`** — Rewritten:
- Removed `github.com/mholt/caddy/caddyhttp/httpserver` import
- Replaced `httpserver.Path(r.URL.Path).Matches(path)` with `strings.HasPrefix(r.URL.Path, path)`
- Same `filter` interface, `securedPathFilter`, `ignoredPathFilter` types

**`setup.go`** — DELETED (merged into `radius.go`)
**`setup_test.go`** — DELETED (v1 tests, to be replaced in Phase 6)

---

### In Progress / Blocked

#### Build verification ⏳
- `go mod tidy` + `go build ./...` started but not yet confirmed clean
- Known issue resolved: `github.com/jamesboswell/radius` internal imports still referenced
  `layeh.com/radius` — fixed by author in commit `8827f2c` on 2026-03-21
- Latest radius pseudo-version in go.mod: `v0.0.0-20260321183830-8827f2c06048`
- `go mod tidy` needed to populate missing go.sum entries for Caddy v2 sub-packages

**Next action**: Run `go mod tidy && go build ./...` to verify clean compile.

---

### Not Started

#### Phase 2 — FreeRADIUS local config
- FreeRADIUS installed via brew at `/opt/homebrew/etc/raddb/`
- Need to: add test user, add 127.0.0.1 NAS client, verify with `radtest`

#### Phase 5 — xcaddy build + smoke test
- Install xcaddy: `go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`
- Build: `xcaddy build --with github.com/jamesboswell/caddy-radius=./`
- Write minimal Caddyfile pointing to local FreeRADIUS
- Test with curl

#### Phase 6 — Tests and CI
- Rewrite tests using `caddytest` package
- Replace `.travis.yml` with GitHub Actions workflow
- Update README with v2 install/config docs

---

## Key Config: New Caddyfile Syntax

```caddyfile
example.com {
    radiusauth {
        server  127.0.0.1:1812
        secret  testing123
        realm   "Restricted"
        cache   /var/lib/caddy
        cache_timeout 5m
        except  /public /health
    }
}
```

## Key Config: JSON equivalent

```json
{
  "handler": "radiusauth",
  "servers": ["127.0.0.1:1812"],
  "secret": "testing123",
  "realm": "Restricted",
  "cache_path": "/var/lib/caddy",
  "cache_timeout": 300000000000
}
```

---

## Dependency Summary

| Package | Version | Purpose |
|---|---|---|
| `github.com/caddyserver/caddy/v2` | v2.11.2 | Caddy v2 framework |
| `github.com/jamesboswell/radius` | v0.0.0-20260321183830-8827f2c06048 | RADIUS client (author's fork) |
| `go.etcd.io/bbolt` | v1.4.3 | Credential cache (bbolt fork of BoltDB) |
| `go.uber.org/zap` | v1.27.1 | Structured logging (transitive via Caddy) |
| `golang.org/x/crypto` | v0.48.0 | bcrypt for cache password hashing |
