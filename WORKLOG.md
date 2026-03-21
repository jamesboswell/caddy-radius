# caddy-radius Modernization Worklog

## Goal
Modernize `github.com/jamesboswell/caddy-radius` from Caddy v1 (circa 2017) to Caddy v2,
updating all dependencies and rewriting the plugin to use the Caddy v2 module system.

---

## Session 1 — 2026-03-21

All work on branch `caddy-v2`. Master is untouched v1 history.

### Phase 1 — Workspace setup ✅
- Initialized `go.mod` (`module github.com/jamesboswell/caddy-radius`, go 1.26.1)
- Migrated BoltDB: `github.com/boltdb/bolt` → `go.etcd.io/bbolt` (drop-in, import alias)

### Phase 2 — Dependency decisions ✅
- **RADIUS library**: `github.com/jamesboswell/radius` (author's fork; fixed module path in commit `8827f2c`)
- **Cache**: keep file-based BoltDB (bbolt) — explicit preference over in-memory

### Phase 3 — Caddy v2 rewrite ✅
Files rewritten:
- **`radius.go`** — `RadiusAuth` struct, `CaddyModule`, `Provision`, `Validate`, `Cleanup`, `ServeHTTP`, `radiusAuth`, `init`, interface guards
- **`caddyfile.go`** — `parseCaddyfile`, `UnmarshalCaddyfile` (split out for readability)
- **`cache.go`** — bbolt import, `RadiusAuth` struct refs, `cachePurge` takes `timeout` param, `openCacheDB` replaces `createCacheDB`
- **`filter.go`** — removed `httpserver` dep, `strings.HasPrefix` replaces `httpserver.Path.Matches`
- **`setup.go`** / **`setup_test.go`** — deleted (merged into `radius.go` / replaced)

Build verified clean: `go mod tidy && go build ./...`

### Phase 4 — FreeRADIUS local config ✅
- FreeRADIUS 3.2.8 via brew (`/opt/homebrew/etc/raddb/`)
- `localhost` NAS + `secret = testing123` already in `clients.conf`
- Test user `testuser / testpass` added to `mods-config/files/authorize` (not the top-level `users` file)
- Verified: `radtest` returns Access-Accept / Access-Reject correctly

### Phase 5 — xcaddy build + smoke test ✅
- `xcaddy build --with github.com/jamesboswell/caddy-radius=./` → `./caddy`
- `Caddyfile.test` on port 8080 (no TLS, `order radiusauth before respond`, bbolt cache at `/tmp/caddy`)
- All scenarios pass: no creds → 401, valid → 200, wrong pass → 401, excepted path → 200

### Phase 6 — Tests ✅
- `radius_test.go`: 20 tests, zero external deps, in-process `radius.PacketServer` mock
  - ServeHTTP (no creds, valid, wrong pass, except, only, cache hit survives RADIUS shutdown)
  - Validate, UnmarshalCaddyfile, filter logic, cache write/seek/expiry/purge, module registration
- All pass with `-race`
- Key trick: `caddy.NewContext(caddy.Context{Context: context.Background()})` for test provisioning

### Phase 7 — CI + README ✅
- `.travis.yml` removed; `.github/workflows/ci.yml` added (Go 1.23, 1.24, stable — vet + race test + xcaddy build)
- README rewritten: xcaddy install, v2 Caddyfile + JSON syntax, improved auth flow diagram
- CI badge updated to GitHub Actions

### Phase 8 — Refactor + release ✅
- `parseCaddyfile` / `UnmarshalCaddyfile` moved to `caddyfile.go`
- Tagged `v2.0.0`
- Pushed `caddy-v2` branch + tag to origin
- Draft PR #3 open: `caddy-v2` → `master` (pending review before merge)

---

## Dependency Summary

| Package | Version | Purpose |
|---|---|---|
| `github.com/caddyserver/caddy/v2` | v2.11.2 | Caddy v2 framework |
| `github.com/jamesboswell/radius` | v0.0.0-20260321183830-8827f2c06048 | RADIUS client (author's fork) |
| `go.etcd.io/bbolt` | v1.4.3 | Credential cache |
| `go.uber.org/zap` | v1.27.1 | Structured logging (transitive via Caddy) |
| `golang.org/x/crypto` | v0.48.0 | bcrypt for cache password hashing |
