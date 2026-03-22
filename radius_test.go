package radiusauth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jamesboswell/radius"
	"github.com/jamesboswell/radius/rfc2865"
)

// startMockRADIUS starts a PacketServer on an available UDP port. It accepts
// requests where username == password (a simple test convention) and rejects
// everything else. Returns the server address and a shutdown function.
func startMockRADIUS(t *testing.T, secret string) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen RADIUS UDP: %v", err)
	}

	srv := &radius.PacketServer{
		SecretSource:       radius.StaticSecretSource([]byte(secret)),
		InsecureSkipVerify: true,
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			user, _ := rfc2865.UserName_LookupString(r.Packet)
			pass, _ := rfc2865.UserPassword_LookupString(r.Packet)
			code := radius.CodeAccessReject
			if user != "" && user == pass {
				code = radius.CodeAccessAccept
			}
			w.Write(r.Response(code)) //nolint:errcheck
		}),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(pc) //nolint:errcheck
	}()

	return pc.LocalAddr().String(), func() {
		srv.Shutdown(t.Context()) //nolint:errcheck
		<-done
	}
}

// okHandler is a caddyhttp.Handler that always returns 200.
var okHandler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// newProvisioned creates a RadiusAuth, provisions it, and registers cleanup.
func newProvisioned(t *testing.T, ra *RadiusAuth) *RadiusAuth {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := ra.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { ra.Cleanup() }) //nolint:errcheck
	return ra
}

// ── ServeHTTP integration tests ──────────────────────────────────────────────

func TestServeHTTP_NoCreds_Returns401(t *testing.T) {
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{Servers: []string{addr}, Secret: "secret"})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ra.ServeHTTP(w, r, okHandler)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic realm=") {
		t.Errorf("missing WWW-Authenticate header: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestServeHTTP_ValidCreds_Returns200(t *testing.T) {
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{Servers: []string{addr}, Secret: "secret"})

	// mock server accepts when user == pass
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("alice", "alice")
	w := httptest.NewRecorder()
	ra.ServeHTTP(w, r, okHandler)

	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
}

func TestServeHTTP_WrongPassword_Returns401(t *testing.T) {
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{Servers: []string{addr}, Secret: "secret"})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("alice", "wrongpass")
	w := httptest.NewRecorder()
	ra.ServeHTTP(w, r, okHandler)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

func TestServeHTTP_ExceptPath_Bypasses(t *testing.T) {
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{
		Servers:     []string{addr},
		Secret:      "secret",
		ExceptPaths: []string{"/public"},
	})

	r := httptest.NewRequest(http.MethodGet, "/public/file.js", nil)
	// no credentials
	w := httptest.NewRecorder()
	ra.ServeHTTP(w, r, okHandler)

	if w.Code != http.StatusOK {
		t.Errorf("excepted path should pass through: got %d", w.Code)
	}
}

func TestServeHTTP_OnlyPath_AuthenticatesMatched(t *testing.T) {
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{
		Servers:   []string{addr},
		Secret:    "secret",
		OnlyPaths: []string{"/admin"},
	})

	// /public should NOT require auth
	r := httptest.NewRequest(http.MethodGet, "/public", nil)
	w := httptest.NewRecorder()
	ra.ServeHTTP(w, r, okHandler)
	if w.Code != http.StatusOK {
		t.Errorf("/public should be open: got %d", w.Code)
	}

	// /admin SHOULD require auth — no creds → 401
	r2 := httptest.NewRequest(http.MethodGet, "/admin/panel", nil)
	w2 := httptest.NewRecorder()
	ra.ServeHTTP(w2, r2, okHandler)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("/admin without creds: got %d, want 401", w2.Code)
	}
}

func TestServeHTTP_Cache_HitSkipsRADIUS(t *testing.T) {
	dir := t.TempDir()
	addr, shutdown := startMockRADIUS(t, "secret")
	defer shutdown()

	ra := newProvisioned(t, &RadiusAuth{
		Servers:      []string{addr},
		Secret:       "secret",
		CachePath:    dir,
		CacheTimeout: caddy.Duration(5 * time.Minute),
	})

	// First request populates the cache
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r1.SetBasicAuth("bob", "bob")
	w1 := httptest.NewRecorder()
	ra.ServeHTTP(w1, r1, okHandler)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w1.Code)
	}

	// Shut down RADIUS — second request must succeed from cache alone
	shutdown()

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.SetBasicAuth("bob", "bob")
	w2 := httptest.NewRecorder()
	ra.ServeHTTP(w2, r2, okHandler)
	if w2.Code != http.StatusOK {
		t.Errorf("cache hit: got %d, want 200 (RADIUS is down)", w2.Code)
	}
}

// ── Validate tests ────────────────────────────────────────────────────────────

func TestValidate_MissingServer(t *testing.T) {
	ra := &RadiusAuth{Secret: "s"}
	if err := ra.Validate(); err == nil {
		t.Error("expected error for missing servers")
	}
}

func TestValidate_MissingSecret(t *testing.T) {
	ra := &RadiusAuth{Servers: []string{"127.0.0.1:1812"}}
	if err := ra.Validate(); err == nil {
		t.Error("expected error for missing secret")
	}
}

func TestValidate_BadServerAddr(t *testing.T) {
	ra := &RadiusAuth{Servers: []string{"notanaddress"}, Secret: "s"}
	if err := ra.Validate(); err == nil {
		t.Error("expected error for bad server address")
	}
}

func TestValidate_ConflictingFilters(t *testing.T) {
	ra := &RadiusAuth{
		Servers:     []string{"127.0.0.1:1812"},
		Secret:      "s",
		ExceptPaths: []string{"/pub"},
		OnlyPaths:   []string{"/admin"},
	}
	if err := ra.Validate(); err == nil {
		t.Error("expected error for both except and only")
	}
}

func TestValidate_Valid(t *testing.T) {
	ra := &RadiusAuth{Servers: []string{"127.0.0.1:1812"}, Secret: "s"}
	if err := ra.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── Caddyfile parsing tests ───────────────────────────────────────────────────

func TestUnmarshalCaddyfile_Basic(t *testing.T) {
	input := `radiusauth {
		server 10.0.0.1:1812
		secret mysecret
		realm "Corp Auth"
		cache /tmp
		cache_timeout 10m
		except /health /metrics
	}`

	d := caddyfile.NewTestDispenser(input)
	ra := &RadiusAuth{}
	if err := ra.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}

	if len(ra.Servers) != 1 || ra.Servers[0] != "10.0.0.1:1812" {
		t.Errorf("servers: %v", ra.Servers)
	}
	if ra.Secret != "mysecret" {
		t.Errorf("secret: %q", ra.Secret)
	}
	if ra.Realm != "Corp Auth" {
		t.Errorf("realm: %q", ra.Realm)
	}
	if ra.CachePath != "/tmp" {
		t.Errorf("cache_path: %q", ra.CachePath)
	}
	if time.Duration(ra.CacheTimeout) != 10*time.Minute {
		t.Errorf("cache_timeout: %v", ra.CacheTimeout)
	}
	if len(ra.ExceptPaths) != 2 {
		t.Errorf("except paths: %v", ra.ExceptPaths)
	}
}

func TestUnmarshalCaddyfile_MultipleServers(t *testing.T) {
	input := `radiusauth {
		server 10.0.0.1:1812 10.0.0.2:1812
		secret s
	}`
	d := caddyfile.NewTestDispenser(input)
	ra := &RadiusAuth{}
	if err := ra.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if len(ra.Servers) != 2 {
		t.Errorf("want 2 servers, got %v", ra.Servers)
	}
}

func TestUnmarshalCaddyfile_CacheTimeoutSeconds(t *testing.T) {
	// backwards-compat: plain integer = seconds
	input := `radiusauth {
		server 127.0.0.1:1812
		secret s
		cache_timeout 300
	}`
	d := caddyfile.NewTestDispenser(input)
	ra := &RadiusAuth{}
	if err := ra.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if time.Duration(ra.CacheTimeout) != 300*time.Second {
		t.Errorf("want 300s, got %v", ra.CacheTimeout)
	}
}

func TestUnmarshalCaddyfile_UnknownOption(t *testing.T) {
	input := `radiusauth {
		server 127.0.0.1:1812
		secret s
		frobnicate yes
	}`
	d := caddyfile.NewTestDispenser(input)
	ra := &RadiusAuth{}
	if err := ra.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected error for unknown option")
	}
}

// ── Filter unit tests ─────────────────────────────────────────────────────────

func TestIgnoredPathFilter(t *testing.T) {
	f := &ignoredPathFilter{ignoredPaths: []string{"/public", "/health"}}

	cases := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"/admin", true},
		{"/public", false},
		{"/public/file.js", false},
		{"/health", false},
		{"/health/check", false},
		{"/healthz", true}, // segment-aware: /healthz is not under /health
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if got := f.shouldAuthenticate(r); got != tc.want {
			t.Errorf("ignoredPathFilter %q: got %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestSecuredPathFilter(t *testing.T) {
	f := &securedPathFilter{securedPaths: []string{"/admin", "/api"}}

	cases := []struct {
		path string
		want bool
	}{
		{"/", false},
		{"/public", false},
		{"/admin", true},
		{"/admin/users", true},
		{"/api/v1", true},
		{"/apiold", false}, // segment-aware: /apiold is not under /api
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if got := f.shouldAuthenticate(r); got != tc.want {
			t.Errorf("securedPathFilter %q: got %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ── Cache unit tests ──────────────────────────────────────────────────────────

func TestCache_WriteAndSeek(t *testing.T) {
	dir := t.TempDir()
	db, err := openCacheDB(dir)
	if err != nil {
		t.Fatalf("openCacheDB: %v", err)
	}
	defer db.Close()

	ra := RadiusAuth{db: db, CacheTimeout: caddy.Duration(5 * time.Minute)}

	if err := cacheWrite(ra, "alice", "pass"); err != nil {
		t.Fatalf("cacheWrite: %v", err)
	}

	ok, err := cacheSeek(ra, "alice", "pass")
	if err != nil || !ok {
		t.Errorf("cacheSeek: ok=%v err=%v", ok, err)
	}

	ok, _ = cacheSeek(ra, "alice", "wrongpass")
	if ok {
		t.Error("wrong password should not be a cache hit")
	}
}

func TestCache_Expiry(t *testing.T) {
	dir := t.TempDir()
	db, err := openCacheDB(dir)
	if err != nil {
		t.Fatalf("openCacheDB: %v", err)
	}
	defer db.Close()

	// 1-millisecond timeout → immediately expired
	ra := RadiusAuth{db: db, CacheTimeout: caddy.Duration(time.Millisecond)}

	if err := cacheWrite(ra, "bob", "pass"); err != nil {
		t.Fatalf("cacheWrite: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	ok, _ := cacheSeek(ra, "bob", "pass")
	if ok {
		t.Error("expired entry should not be a cache hit")
	}
}

func TestCache_Purge(t *testing.T) {
	dir := t.TempDir()
	db, err := openCacheDB(dir)
	if err != nil {
		t.Fatalf("openCacheDB: %v", err)
	}
	defer db.Close()

	ra := RadiusAuth{db: db, CacheTimeout: caddy.Duration(time.Millisecond)}
	cacheWrite(ra, "u1", "p") //nolint:errcheck
	cacheWrite(ra, "u2", "p") //nolint:errcheck
	time.Sleep(5 * time.Millisecond)

	count, err := cachePurge(db, time.Millisecond)
	if err != nil {
		t.Fatalf("cachePurge: %v", err)
	}
	if count != 2 {
		t.Errorf("want 2 purged, got %d", count)
	}
}

// ── Module registration ───────────────────────────────────────────────────────

func TestCaddyModule(t *testing.T) {
	info := RadiusAuth{}.CaddyModule()
	if info.ID != "http.handlers.radiusauth" {
		t.Errorf("module ID: %q", info.ID)
	}
	if info.New == nil {
		t.Error("New must not be nil")
	}
}

// ── TestMain: skip if no RADIUS capability needed ─────────────────────────────

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
