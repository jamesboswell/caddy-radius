package radiusauth

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	// c := caddy.NewTestController("http", "radiusauth {\n server localhost:1812\nsecret TOOMANYSECRETS\n}")
	c := caddy.NewTestController("http",
		`radiusauth {
          server localhost:1812
          secret TOOMANYSECRETS
          }`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(RADIUS)
	if !ok {
		t.Fatalf("Expected handler to be type RADIUS, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestRADIUSAuthParse(t *testing.T) {

	tests := []struct {
		inputRADIUSConfig    string
		shouldErr            bool
		expectedRADIUSConfig radiusConfig
	}{
		// Test 0
		{`radiusauth {
          server localhost:1812
          secret TOOMANYSECRETS
          realm "Private"
          cache /tmp
          cachetimeout 300
          nasid "Caddy"
          except /public /assests
          }`,
			false, radiusConfig{

				Server: []string{"localhost:1812"},
				Secret: "TOOMANYSECRETS",
				// Timeout:       3,
				// Retries:       1,
				nasid:         "Caddy",
				realm:         "Private",
				requestFilter: &ignoredPathFilter{ignoredPaths: []string{"/public", "/assests"}},
				cache:         "/tmp",
				cachetimeout:  300000000000, // nanoseconds
			}},
		// Test 1 - test 'except' + 'only' filters - SHOULD FAIL
		{`radiusauth {
		      server 127.0.0.1:1812
		      secret TOOMANYS3cret5
          except /public
          only /private
		      }`,
			true, radiusConfig{

				Server:  []string{"127.0.0.1:1812"},
				Secret:  "TOOMANYS3cret5",
				Timeout: 3,
				Retries: 1,
				nasid:   "Caddy",
				// realm:         "Private",
				requestFilter: nil,
				cache:         "/tmp",
				cachetimeout:  60,
			}},
		// Test 2 - only paths should start with a /
		{`radiusauth {
		      server 127.0.0.1:1812
		      secret TOOMANYS3cret5
          only /private secret
		      }`,
			true, radiusConfig{

				Server: []string{"127.0.0.1:1812"},
				Secret: "TOOMANYS3cret5",
				// Timeout: 3,
				// Retries: 1,
				// nasid:   "Caddy",
				// // realm:         "Private",
				// requestFilter: nil,
				// cache:         "/tmp",
				// cachetimeout:  60,
			}},
		// Test 3 - except paths should start with a /
		{`radiusauth {
		      server 127.0.0.1:1812
		      secret TOOMANYS3cret5
          except /public assests
		      }`,
			true, radiusConfig{

				Server: []string{"127.0.0.1:1812"},
				Secret: "TOOMANYS3cret5",
				// Timeout: 3,
				// Retries: 1,
				// nasid:   "Caddy",
				// // realm:         "Private",
				// requestFilter: nil,
				// cache:         "/tmp",
				// cachetimeout:  60,
			}},
		// Test 4 - server argument must be provided
		{`radiusauth {
          server 127.0.0.1
          secret TOOMANYS3cret5
          nasid "Caddy"
		      }`,
			true, radiusConfig{
				Server: []string{"127.0.0.1"},
				Secret: "TOOMANYS3cret5",
				nasid:  "Caddy",
			}},
	}

	for i, test := range tests {

		actualRadiusAuthConfigs, err := parseRadiusConfig(caddy.NewTestController("http", test.inputRADIUSConfig))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if err != nil && test.shouldErr {
			// If shouldErr don't test individual values
			break
		}

		a := &actualRadiusAuthConfigs
		b := &test.expectedRADIUSConfig

		if reflect.DeepEqual(a.Server, b.Server) == false {
			t.Errorf("Test %d expected server to be %s, but got %s",
				i, a.Server, b.Server)
		}
		if reflect.DeepEqual(a.Secret, b.Secret) == false {
			t.Errorf("Test %d expected secret to be %s, but got %s",
				i, a.Secret, b.Secret)
		}
		if reflect.DeepEqual(a.realm, b.realm) == false {
			t.Errorf("Test %d expected realm to be %s, but got %s",
				i, a.realm, b.realm)
		}
		if reflect.DeepEqual(a.requestFilter, b.requestFilter) == false {
			t.Errorf("Test %d expected filter to be %#v, but got %#v",
				i, a.requestFilter, b.requestFilter)

		}

	}
}
