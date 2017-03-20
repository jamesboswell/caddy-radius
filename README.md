# caddy-radius

caddy-radius is a [Caddy](https://caddyserver.com/) plugin that implements
HTTP Basic Access Authentication using a [RADIUS](https://en.wikipedia.org/wiki/RADIUS) server for user authentications.

When a user requests a resource that is protected, the browser will prompt for a username and password if they have not already supplied one.  The user credentials are sent to a configured RADIUS server for authentication.  Upon successful RADIUS authentication (Access-Accept), the server will grant access to the resource.
> NOTE:  RADIUS has relatively weak security. Communication between the Caddy server and the RADIUS server should be on trusted networks or separately secured via IPsec or other mechanisms which are outside the scope of this plugin.

After a successful RADIUS authentication, credentials are stored in a local cache with a cache TTL in seconds as configured in caddyfile (`cachetimeout`).  Subsequent HTTP requests will use the cached entry, reducing load on the RADIUS servers as well as response time to HTTP requests.

When cached entries are older than `cachetimeout` a new RADIUS authentication will be performed.

If Authorization headers DO NOT match the cached entry for a particular user, a fresh RADIUS authentication will be performed.

Authentication flow in pseudo-code
```
if user in cache AND password matches:
   if TTL > cachetimeout (expired):
      perform RADIUS authentication
   else GrantAccess
if user in cache AND password DOES NOT match:
    perform RADIUS authentication
if user NOT in cache:
    perform RADIUS authentication
if RADIUS authentication successful:
    add user to cache with TTL of cachetimeout
    GrantAccess
if RADIUS authentication NOT successful:
    Deny Access
    HTTP error 401
```

### RADIUS servers
caddy-radius has been tested against CiscoSecure ACS 5.4 and FreeRADIUS 3.0.13


### Caddyfile
Add a **radiusauth** term to your caddyfile
```
radiusauth {
        server 1.2.3.4:1812
        secret SuperAWesomeSecret
        realm  "RADIUS Auth"
        except /public
        cache  /var/cache
        cachetimeout 30
}
```
* server - RADIUS server in host:port format
* secret - RADIUS shared secret
* realm  - Basic Auth realm message (ex: ACME Inc.)
* except - path to NOT enable authentication on
* cache  - location to store cache file
* cachetimeout - time in seconds authentication entries should be cached


## TODO:
- [ ] Implement RADIUS server failover
- [ ] finish path filtering (needs more testing)
- [ ] allow disabling of cache
- [x]every HTTP GET is a RADIUS transaction, need to reduce
  * ~~implement some kind of cache~~
    * ~~bcrypt hash of user/password that expires at X minutes~~

#### Inspired by
caddy-radius draws on ideas from  [mod_auth_xradius](http://www.outoforder.cc/projects/httpd/mod_auth_xradius/) for Apache which inspired it's creation

## DISCLAIMER
This software is provided as is for free and public use.  No warranties or claims of quality or security are made.  Users should perform their own security analysis and acknowledge and accept the risks as stated.
