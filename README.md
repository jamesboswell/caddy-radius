
**THIS IS A WORK IN PROGRESS, not yet fully functional**

# caddy-radius

caddy-radius is a [Caddy](https://caddyserver.com/) plugin that enables
user authentication against a [RADIUS](https://en.wikipedia.org/wiki/RADIUS) server

Inspired by
* http://www.outoforder.cc/projects/httpd/mod_auth_xradius/
* http://freeradius.org/mod_auth_radius/



### Caddyfile
Add a **radiusauth** term to your caddyfile
```
radiusauth {
        server 1.2.3.4:1812
        secret SuperAWesomeSecret
        realm  "RADIUS Auth"
        except /public
}
```
* server - RADIUS server in host:port format
* secret - RADIUS shared secret
* realm  - Basic Auth realm message (ex: ACME Inc.)
* except - path to NOT enable authentication on


## TODO:
* finish path filtering
* every HTTP GET is a RADIUS transaction, need to reduce
  * implement some kind of cache, pseudo code:
    * bcrypt hash of user/password that expires at X minutes
      * if inCache && CompareHashandPassword && filteredPath
        * authenticate
      * else  auth()
