k-http
======

[![Build Status](https://api.travis-ci.org/andrasq/node-k-http.svg?branch=master)](https://travis-ci.org/andrasq/node-k-http?branch=master)
[![Coverage Status](https://codecov.io/github/andrasq/node-k-http/coverage.svg?branch=master)](https://codecov.io/github/andrasq/node-k-http?branch=master)

Thin, light-weight convenience wrapper around http and https.
Makes web requests kinda like `qhttp`, returns responses kinda like `request`.


Example
-------

    var khttp = require('k-http');

    var requestBody = { n: 1234 }
    khttp.request("http://example.com", requestBody, function(err, res, responseBody) {
        // ...
    })

    var sendBody = { m: 5678 }
    khttp.post("http://example.com", sendBody, function(err, res, responseBody) {
        // ...
    })


Api
---

### khttp.request( optionsOrUrl, [body,] callback(err, res, body) )

Make a web request to the url string or target specified by the options.
The options are passed directly to `http.request` or `https.request`.

Arguments:
- `optionsOrUrl` - remote service specification, either as a url string
  or an http options object.  String urls use `GET`.
- `body` - request body to send, optional.  Can be a string, Buffer or object.
  Strings and Buffers are sent as-is, all other types (objects, numbers, etc)
  are json stringified before being sent.
- `callback` - function to receive the response.  The callback is passed any error
  `err`, the response object `res`, and the response body `body`.  The response is
  annotated with `res.body` = `body`.  The returned `body` can be a string, a Buffer,
  or an object, depending on `options.encoding` and `options.json`.

k-http options (kinda like `request`):
- `url` - remote host to connect to, specified as a string in the form
  protocol://host/path?query
- `body` - request body to send, as described above (default empty string "").
  A body passed as a function parameter overrides a body passed in options.
- `query` - query string to append to the path, without the leading `?` (default none)
- `encoding` - how to decode the response.  Set to `null` to return the raw
  response bytes in a Buffer, else returns a string converted with `toString(encoding)`
  (default 'utf8' strings)
- `json` - supply a Content-Type request header of application/json unless already set,
  and parse the response body string into a json object and return the object.
  If the response is not valid json, returns the response string.
- `auth` - object with fields `{ username: , password: }` used to build an
  "Authorization: Basic" header.  The fields `{ user: , pass: }` are also accepted.
- `raw` - do not wait for and decode body, return immediately and let the caller
  wait for `res.on('data')` events.
- `retryCount` - number of times to attempt the call in case of connection errors.
  Default 0, no retries.
- `retryError` - list of error codes to retry if `retryCount` > 0.  Default is
  `['ECONNRESET']` socket disconnects.

http options used to construct a url from parts:
- `protocol` - 'http:' or 'https:' (default 'http:')
- `method` - http verb of the request (default 'GET')
- `host` - name of remote host to connect to.  Do not include the port,
  it breaks http (default `localhost`)
- `hostname` - name of remote host to connect to (default `localhost`)
- `port` - remote port to connect to (default `80`)
- `path` - resource path to access (default `/`)

Other options are presumed to be http options and are passed to the request.

### khttp.defaults( optionsOrUrl )

Construct a pre-configured caller with a method `request` that will use
khttp.request to make calls.

The options are as in khttp.request.  Call-time options provided to
`callre.request` override the default options.

### khttp.call( method, optionsOrUrl, [body,] callback(err, res, body) )

Call `request` with the specified method.

### khttp.get( optionsOrUrl, [body,] callback(err, res, body) )

The `call` method is also accessible as the conveinence methods `get`, `post`,
`put`, `head`, `del`, and `patch`, which invoke `call` with the appropriate method.


Related Work
------------

- [request](http://npmjs.org/package/request)
- [qhttp](http://npmjs.org/package/qhttp)
- [restify jsonClient](http://npmjs.org/package/restify)


Chane Log
---------

- 1.4.0 - new `retryCount` option
- 1.3.6 - fix: fix url + path combo, fix: send empty request body if `null` or `undefined`
- 1.3.5 - make defaults() inherit settings from parent
- 1.3.4 - fix headers edge case, simplify optimizeAccess, coverage buttons
- 1.3.1 - fix headers merging to always copy, 100% code coverage
- 1.3.0 - fix options merging, add `get`/`put`/`post` etc aliases
- 1.2.0 - harden socket timeout handling
- 1.1.0 - `defaults()` function to return a pre-configured caller
- 1.0.1 - speed access to res.body, readme edits
- 1.0.0 - initial checkin
