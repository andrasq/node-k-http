/**
 * Copyright (c) 2016-2017, Kinvey, Inc. All rights reserved.
 *
 * This software is licensed to you under the Kinvey terms of service located at
 * http://www.kinvey.com/terms-of-use. By downloading, accessing and/or using this
 * software, you hereby accept such terms of service  (and any agreement referenced
 * therein) and agree that you have read, understand and agree to be bound by such
 * terms of service and are of legal age to agree to such terms with Kinvey.
 *
 * This software contains valuable confidential and proprietary information of
 * KINVEY, INC and is subject to applicable licensing agreements.
 * Unauthorized reproduction, transmission or distribution of this file and its
 * contents is a violation of applicable laws.
 */

'use strict';

var assert = require('assert');
var http = require('http');
var https = require('https');
var events = require('events');
var khttp = require('./');

var echoService = 'http://localhost:1337';
var pingService = echoService + '/ping';
var slowCallMs = 100;

// quick cpuUsage() for eg node-v0.10
if (!process.cpuUsage) {
    var os = require('os');
    process.cpuUsage = function( usage ) {
        var cpus = os.cpus();
        // os.cpu uses 100us units, cpuUsage uses 1us
        var user = 0, system = 0;
        for (var i=0; i<cpus.length; i++) {
            user +=  cpus[i].times.user * 100;
            system += cpus[i].times.sys * 100;
        }
        return (usage)
            ? { user: user - usage.user, system: system - usage.system }
            : { user: user, system: system };
    }
}

describe ('khttp', function() {
    var echoServer;
    var echoRequest = null;
    var echoCallCount = 0;
    var singletonCall;
    var uniq = null;

    before (function(done) {
        echoServer = http.createServer(function(req, res) {
            echoCallCount += 1;
            var chunks = [];
            req.on('data', function(chunk) {
                chunks.push(chunk);
            })
            req.on('end', function() {
                echoRequest = Buffer.concat(chunks);
                var echoResponse = JSON.stringify({
                    url: req.url,
                    method: req.method,
                    headers: req.headers,
                    rawHeaders: req.rawHeaders,
                    body: echoRequest.toString(),
                });
                if (/^\/ping/.test(req.url)) {
                    return res.end('PONG:' + echoResponse);
                }
                else switch (req.url) {
                case '/':
                case '/default':
                default:
                    return res.end(echoResponse);
                case '/slowcall':
                    res.write(echoResponse.slice(0, 1));
                    return setTimeout(function() { res.end(echoResponse.slice(1)) }, slowCallMs);
                case '/badjson':
                    return res.end("{error");
                case '/responseerror':
                    return res.socket.destroy();
                case '/notjson':
                    return res.end("not json:" + echoResponse);
                case '/garbled':
                    return res.socket.write("bad response\r\n\r\n");
                case '/notfound':
                    res.statusCode = 404;
                    return res.end(req.path + ": Not Found");
                }
            })
            req.on('error', function(err) {
                throw err;
            })
        })
        echoServer.on('error', function(err) {
            throw err;
        })
        echoServer.once('listening', done);
        echoServer.listen(1337);
    })

    beforeEach(function(done) {
        uniq = (Math.random() * 0x1000000).toString(16);
        echoRequest = null;
        done();
    })

    afterEach(function(done) {
        khttp.allowDuplicateCallbacks = false;
        done();
    })

    after (function(done) {
        echoServer.close();
        setTimeout(done, 20);
    })


    it ('should parse package', function(done) {
        require('./package.json');
        done();
    })

    it ('should export expected properties', function(done) {
        assert.equal(typeof khttp.request, 'function');
        assert.equal(typeof khttp.defaults, 'function');
        assert.equal(typeof khttp.get, 'function');
        assert.equal(typeof khttp.post, 'function');
        assert.equal(typeof khttp.del, 'function');
        assert.equal(typeof khttp.allowDuplicateCallbacks, 'boolean');
        done();
    })

    it ('defaults should have expected properties', function(done) {
        var defaults = khttp.defaults();
        assert.equal(typeof defaults.request, 'function');
        assert.equal(typeof defaults.defaults, 'function');
        assert.equal(typeof defaults.get, 'function');
        assert.equal(typeof defaults.post, 'function');
        assert.equal(typeof defaults.del, 'function');
        done();
    })

    it ('should make a request to a url string', function(done) {
        khttp.request(echoService, function(err, res, body) {
            assert.ifError(err);
            assert.equal(JSON.parse(body).url, '/');
            assert.equal(JSON.parse(body).method, 'GET');
            done();
        })
    })

    it ('should make a request to the url with query and body', function(done) {
        khttp.request({ url: pingService, body: uniq, query: 'a=1&b=2', headers: {Connection: 'close'} }, function(err, res, body) {
            assert(body.indexOf('PONG:') === 0);
            body = JSON.parse(body.slice(5));
            assert.equal(body.url, '/ping?a=1&b=2');
            assert.equal(body.body, uniq);
            assert.equal(body.headers.connection, 'close');
            done();
        })
    })

    it ('should make a request to the host, port, path', function(done) {
        khttp.request({ host: 'localhost', port: 1337, body: uniq, query: 'a=11&b=22', path: '/default' }, function(err, res, body) {
            body = JSON.parse(body);
            assert.equal(body.url, '/default?a=11&b=22');
            assert.equal(body.body, uniq);
            done();
        })
    })

    it ('should combine base url with path', function(done) {
        var caller = khttp.defaults({ url: 'http://localhost:1337' })
        caller.get({ query: 'a=123', path: '/default' }, function(err, res, body) {
            body = JSON.parse(body)
            assert.equal(body.url, '/default?a=123');
            done();
        })
    })

    it ('should combine partial url with path', function(done) {
        var caller = khttp.defaults({ url: 'http://localhost:1337/partial' })
        caller.get({ query: 'a=123', path: '/path' }, function(err, res, body) {
            body = JSON.parse(body)
            assert.equal(body.url, '/partial/path?a=123');
            done();
        })
    })

    it ('should send empty body if null', function(done) {
        khttp.request(echoService, null, function(err, res, body) {
            assert.strictEqual(JSON.parse(body).body, "");
            done();
        })
    })

    it ('should accept url as a function parameter', function(done) {
        khttp.request({ url: echoService, body: 'some test body' }, uniq, function(err, res, body) {
            assert.ifError(err);
            assert.equal(JSON.parse(body).body, uniq);
            done();
        })
    })

    it ('should append query to path', function(done) {
        khttp.request({ url: echoService + '?a=1', body: uniq, query: 'b=2' }, function(err, res, body) {
            body = JSON.parse(body);
            assert.equal(body.url, '/?a=1&b=2');
            done();
        })
    })

    it ('should use the specified method', function(done) {
        khttp.request({ url: echoService, method: 'post', body: uniq }, function(err, res, body) {
            assert.ifError(err);
            body = JSON.parse(body);
            assert.equal(body.method, 'POST');
            assert.equal(body.body, uniq);
            done();
        })
    })

    it ('should include the passed headers', function(done) {
        khttp.request({ url: echoService, headers: {'x-uniq': uniq} }, function(err, res, body) {
            assert.ifError(err);
            assert.equal(JSON.parse(body).headers['x-uniq'], uniq);
            done();
        })
    })

    it ('should return the client request object', function(done) {
        var req = khttp.request({ url: echoService }, function(err, res, body) { });
        assert(req instanceof http.ClientRequest);
        done();
    })

    it ('should return the response body', function(done) {
        var req = khttp.request({ url: echoService, body: uniq }, function(err, res, body) {
            assert(res instanceof http.IncomingMessage);
            assert(typeof body === 'string');
            assert(res.body === body);
            assert(body.indexOf('"body":"' + uniq) > 0);
            done();
        })
    })

    it ('should return connect timeout error', function(done) {
        // hit a valid (plausible) ip address that does not respond
        var startTime = Date.now()
        khttp.request({ host: '10.0.0.1', path: '/', timeout: 20 }, function(err, res, body) {
            assert(err);
            assert(Date.now() - startTime < 50);
            assert.equal(err.code, 'ETIMEDOUT');
            done();
        })
    })

    it ('should time out socket', function(done) {
        khttp.request({ url: echoService + '/slowcall', timeout: slowCallMs / 5 }, function(err, res, body) {
            assert(err);
            assert.equal(err.code, 'ESOCKETTIMEDOUT');
            done();
        })
    })

    it ('should return socket error', function(done) {
        khttp.request({ url: echoService + '/responseerror' }, function(err, res, body) {
            assert(err);
            assert(err.toString().indexOf('socket hang up') >= 0);
            done();
        })
    })

    describe ('retried call', function() {
        it ('should return socket error', function(done) {
            var callCount = echoCallCount;
            khttp.request(
                { url: echoService + '/responseerror', retryCount: 2 },
                function(err, res, body) {
                    assert(err);
                    assert.equal(err.code, 'ECONNRESET');
                    assert.equal(echoCallCount, callCount + 1 + 2);
                    done();
                }
            );
        })

        it ('should use default options', function(done) {
            var client = khttp.defaults({ url: echoService, headers: { 'my-marker': 'test' } });
            client.request({}, 'mockRequestBody', function(err, res, body) {
                assert(!err);
                assert(body.indexOf('"my-marker":"test"') > 0);
                assert(body.indexOf('"url":"/"') > 0);
                client.request(
                    { url: echoService + '/someValidUrl', retryCount: 2 },
                    function(err, res, body) {
                        assert(!err);
                        assert(body.indexOf('"my-marker":"test"') > 0);
                        assert(body.indexOf('"url":"/someValidUrl"') > 0);
                        done();
                    }
                );
            })
        })

        it ('should retry call and return socket error', function(done) {
            var callArgs = [];
            var savedRequest = http.request;
            http.request = function(options, cb) {
                callArgs.push(arguments);
                var cb = arguments[arguments.length - 1];
                var res = new events.EventEmitter();
                setImmediate(cb, res);
                setImmediate(function(){ res.emit('error', { code: 'EMOCK', message: 'mock http error' }) });
                var req = new events.EventEmitter();
                req.end = function(){};
                return req;
            };
            khttp.request({ url: 'http://localhost:12345/nonesuch', retryCount: 7, retryErrors: ['ETIMEDOUT', 'EMOCK'] }, function(err, res, body) {
                http.request = savedRequest;
                assert(err);
                assert.equal(err.code, 'EMOCK');
                assert.equal(callArgs.length, 1 + 7);
                done();
            })
        })
    })

    it ('should return response error', function(done) {
        khttp.allowDuplicateCallbacks = true;
        khttp.request({ url: echoService }, function(err, res, body) {
            if (!err) res.emit('error', new Error('deliberate res error'));
            if (err) {
                khttp.allowDuplicateCallbacks = false;
                done();
            }
        })
    })

    it ('should accept keepAlive Agent to reuse connection', function(done) {
        var agent = new http.Agent({ keepAlive: true });
        khttp.request({ url: echoService, agent: agent }, function(err, res, body) {
            assert.ifError(err);
            body = JSON.parse(body);
            assert.equal(body.headers.connection, 'keep-alive');
            done();
        })
    })

    it ('should reuse keepAlive connection without too many listeners error', function(done) {
        var agent = new http.Agent({ keepAlive: true });
        var callCount = 0;
        var t1 = Date.now();
        var cpu1 = process.cpuUsage();
        (function testLoop() {
            khttp.request({ url: echoService, agent: agent }, function(err, res, body) {
                callCount += 1;
                if (err) return done(err);
                if (callCount < 200) {
                    setImmediate(testLoop);
                }
                else {
                    var cpu = process.cpuUsage(cpu1);
                    var t2 = Date.now();
                    console.log("%s: %d http calls in %d ms, total cpu %d ms (%d bytes)",
                        khttp.request.name, callCount, t2-t1, cpu.user/1000 + cpu.system/1000, body.length);
                    // note: 58ms elapsed < 80ms cpu due to i/o threads; run on a single core to get elapsed >= cpu used
                    return done();
                }
            })
        })();
    })

    it ('should accept string body', function(done) {
        khttp.request({ url: echoService, body: uniq.toString() }, function(err, res, body) {
            assert.ifError(err);
            assert.strictEqual(JSON.parse(body).body, uniq.toString());
            done();
        })
    })

    it ('should accept Buffer body', function(done) {
        khttp.request({ url: echoService, body: new Buffer(uniq.toString()) }, function(err, res, body) {
            assert.ifError(err);
            assert.strictEqual(JSON.parse(body).body, uniq.toString());
            done();
        })
    })

    it ('should accept object body', function(done) {
        khttp.request({ url: echoService, body: {uniq: uniq} }, function(err, res, body) {
            assert.ifError(err);
            assert.deepEqual(JSON.parse(JSON.parse(body).body), {uniq: uniq});
            done();
        })
    })

    it ('should accept non-string, non-object body', function(done) {
        khttp.request({ url: echoService, body: 1234 }, function(err, res, body) {
            assert.ifError(err);
            assert.strictEqual(JSON.parse(body).body, '1234');
            done();
        })
    })

    it ('should send binary data', function(done) {
        var data = new Buffer(256);
        for (var i=0; i<256; i++) data[i] = i;
        khttp.request({ method: 'POST', url: echoService, body: data }, function(err, res, body) {
            assert.deepEqual(echoRequest, data);
            done();
        })
    })

    it ('should send utf8 strings', function(done) {
        var str = '';
        // skip the troublesome code points D800..DFFF which encode to FFFD but charCodeAt(i) remains D800
        for (var i=0; i<65536; i++) str += (i < 0xD800 || i > 0xDFFF) ? String.fromCharCode(i) : ' ';
        khttp.request({ method: 'POST', url: echoService, body: str }, function(err, res, body) {
            assert.strictEqual(JSON.parse(body).body, str);
            done();
        })
    })

    it ('encoding:null should return a Buffer of bytes', function(done) {
        khttp.request({ url: echoService, encoding: null }, function(err, res, body) {
            assert(Buffer.isBuffer(body));
            done();
        })
    })

    it ('json:true should make application/json request and decode response into object', function(done) {
        khttp.request({ url: echoService, json: true, body: { uniq: uniq } }, function(err, res, body) {
            assert.ifError(err);
            assert(typeof body === 'object');
            assert.equal(body.headers['content-type'], 'application/json');
            assert.deepEqual(JSON.parse(body.body), {uniq: uniq});
            done();
        })
    })

    it ('json:true should return non-json strings as-is', function(done) {
        khttp.request({ url: echoService + '/notjson', json: true, body: {a: uniq} }, function(err, res, body) {
            assert.ifError(err);
            assert.equal(typeof body, 'string');
            assert(body.indexOf('not json:') == 0);
            done();
        })
    })

    it ('json:true should not overwrite user specified content-type', function(done) {
        khttp.request({ url: echoService, json: true, body: {uniq: uniq}, headers: {'content-type': 'user-content-type'} }, function(err, res, body) {
            assert.ifError(err);
            assert(typeof body === 'object');
            assert.equal(body.headers['content-type'], 'user-content-type');
            done();
        })
    })

    it ('json:true should send non-json capable objects as plaintext', function(done) {
        var nthCall = 0;
        var requestBody = { toJSON: function() { throw new Error("not json capable") } };
        khttp.request({ url: echoService, json: true }, requestBody, function(err, res, body) {
            assert.equal(body.body, '[object Object]');
            done();
        })
    })

    it ('auth:{user,pass} should be converted into Authorization header', function(done) {
        var uri = { url: echoService, auth: {user: 'test1', pass: 'test2'}, json: true };
        khttp.request(uri, function(err, res, body) {
            assert.equal(body.headers.authorization, 'Basic ' + new Buffer('test1:test2').toString('base64'));
            done();
        })
    })

    it ('auth:{username,password} should be converted into Authorization header', function(done) {
        var uri = { url: echoService, auth: {username: 'test3', password: 'test4'}, json: true };
        khttp.request(uri, function(err, res, body) {
            assert.equal(body.headers.authorization, 'Basic ' + new Buffer('test3:test4').toString('base64'));
            done();
        })
    })

    it ('should make https calls', function(done) {
        khttp.request({ url: "https://google.com" }, function(err, res, body) {
            assert.ifError(err);
            assert.equal(res.statusCode, 301);
            done();
        })
    })

    it ('should callback only once', function(done) {
        var calledCount = 0;
        var req = khttp.request({ url: "http://localhost:1337" }, function(err, res, body) {
            calledCount += 1;
            req.emit('error', new Error("deliberate response error"));
            if (calledCount > 1) return done(new Error("too many callbacks"));
            setTimeout(function(){ done() }, 50);
        })
    })

    describe ('options', function() {
        it ('options.raw should not wait for body', function(done) {
            var request = khttp.defaults({ raw: true }).request;
            request(echoService, function(err, res) {
                assert.ifError(err);
                var chunks = [];
                res.on('data', function(chunk) {
                    chunks.push(chunk);
                })
                res.on('end', function() {
                    assert(chunks.length > 0);
                    done();
                })
            })
        })

        it ('options.raw should time out', function(done) {
            var request = khttp.defaults({ raw: true }).request;
            request({ url: echoService + '/slowcall', timeout: slowCallMs / 5 }, function(err, res, body) {
                assert(!err);
                res.on('error', function(err) {
                    assert.equal(err.code, 'ESOCKETTIMEDOUT');
                    done();
                })
            })
        })
    })

    describe ('defaults', function() {
        it ('should construct a caller', function(done) {
            var caller = khttp.defaults({ url: "http://example.com", headers: { uniq: uniq } });
            assert.equal(caller.opts.url, "http://example.com");
            assert.deepEqual(caller.opts.headers, { uniq: uniq });
            assert.equal(typeof caller.request, 'function');
            done();
        })

        it ('should use khttp.request to make request', function(done) {
            var caller = khttp.defaults({ json: true, headers: { 'Content-Length': -1 } });
            var called = false;
            var krequest = khttp.request;
            khttp.request = function(url, body, cb) { called = true; krequest(url, body, cb) };
            caller.request("http://localhost:1337", function(err, res, body) {
                khttp.request = krequest;
                assert.ifError(err);
                assert.equal(called, true);
                assert.equal(typeof body, 'object');
                assert.equal(body.headers['content-length'], 0);
                done();
            })
        })

        it ('should save options', function(done) {
            var a = {a:1, b:2};
            var b = khttp.defaults(a);
            assert.deepEqual(b.opts, a);
            done();
        })

        it ('should pass headers to request', function(done) {
            var caller = khttp.defaults({ url: "http://localhost:1337" });
            caller.request({ json: true, headers: { 'x-tracer': uniq } }, function(err, res, body) {
                assert.equal(body.headers['x-tracer'], uniq);
                done();
            })
        })

        it ('should omit undefined headers', function(done) {
            var caller = khttp.defaults({ url: "http://localhost:1337" });
            caller.request({ json: true, headers: { 'x-tracer': uniq, 'x-empty': undefined } }, function(err, res, body) {
                assert.equal(body.headers['x-tracer'], uniq);
                assert(!('x-empty' in body.headers));
                done();
            })
        })

        it ('should override options', function(done) {
            var caller = khttp.defaults({ url: "http://localhost:1337", json: true, encoding: 'utf8' });
            caller.request({ json: false, encoding: null }, function(err, res, body) {
                assert.ifError(err)
                assert.ok(Buffer.isBuffer(body), "expected Buffer, got: " + (body));
                done();
            })
        })

        it ('should merge in options headers', function(done) {
            var caller = khttp.defaults({ headers: {'header-1': 'value-1'} });
            assert.ok(caller.opts);
            assert.equal(caller.opts.headers['header-1'], 'value-1');
            done();
        })

        it ('should inherit from parent', function(done) {
            var caller1 = khttp.defaults({ url: "http://localhost:1337", headers: {'header-1': 'value-1'} });
            var caller2 = caller1.defaults({ headers: {'header-2': 'value-2'} });
            assert.equal(caller2.opts.url, "http://localhost:1337");
            assert.deepEqual(caller2.opts.headers, { 'header-1': 'value-1', 'header-2': 'value-2' });
            done();
        })
    })

    describe ('shortcuts', function() {
        it ('should make a get request', function(done) {
            khttp.get("http://localhost:1337", "body", function(err, res, body) {
                assert.ifError(err);
                assert.equal(JSON.parse(body).method, 'GET');
                done();
            })
        })

        it ('should make a post request', function(done) {
            khttp.post("http://localhost:1337", "body", function(err, res, body) {
                assert.ifError(err);
                assert.equal(JSON.parse(body).method, 'POST');
                done();
            })
        })

        it ('should make a del request', function(done) {
            khttp.del("http://localhost:1337", "body", function(err, res, body) {
                assert.ifError(err);
                assert.equal(JSON.parse(body).method, 'DELETE');
                done();
            })
        })

        it ('defaults should have a get method', function(done) {
            var defaults = khttp.defaults({ url: "http://localhost:1337" });
            defaults.get("/path/to/resource", "body", function(err, res, body) {
                assert.ifError(err);
                assert.equal(JSON.parse(body).method, 'GET');
                assert.equal(JSON.parse(body).url, '/path/to/resource');
                done();
            })
        })

        it ('shortcuts should invoke .call', function(done) {
            var caller = khttp.defaults({});
            var methods = { get: 'GET', head: 'HEAD', post: 'POST', put: 'PUT', patch: 'PATCH', del: 'DELETE' };
            var lastMethodCalled = null;
            caller.call = function(method, url, body, cb) {
                lastMethodCalled = method;
            }
            for (var method in methods) {
                caller[method]("url", "body", function cb(){});
                assert.equal(lastMethodCalled, methods[method]);
            }
            done();
        })
    })

    describe ('performance', function() {
        it ('should use little cpu', function(done) {
            //var khttpClient = khttp.defaults({ agent: new http.Agent({ keepAlive: true, maxSockets: 10, maxFreeSockets: 2 }) });
            var requestCaller = function httpRequest(uri, cb) {         // 96 ms cpu for 400 calls to bing, +0% (1.6 sec elapsed)
                var req = http.request(uri, function(res) {
                    var chunks = [];
                    res.on('data', function(chunk) { chunks.push(chunk) });
                    res.on('end', function() { cb(null, res, Buffer.concat(chunks)) });
                })
                req.end(uri.body);
            };
            var requestCaller = khttp.request;                          // 124 ms cpu for 400 calls to bing, +29% (2 sec elapsed)
            //var requestCaller = require('request');                     // 1012 ms cpu for 400 calls to bing, +954% (14.7 sec elapsed)
            var doneCount = 0;
            var cpu = process.cpuUsage();
            var t1 = Date.now();
            var uri = {
                //url: "https://google.com/login",        // 1.5k, 30ms
                url: "http://bing.com/",                // 256b, 21ms
            }
            for (var callCount=0; callCount<10; callCount++) {
                requestCaller(uri, callDone);
            }
            function callDone(err, res, body) {
                doneCount += 1;
                if (doneCount === callCount) {
                    var t2 = Date.now();
                    cpu = process.cpuUsage(cpu);
                    console.log("%s: %d https calls in %d ms, total cpu %d ms (%d bytes)",
                        requestCaller.name, callCount, t2-t1, cpu.user/1000 + cpu.system/1000, body.length);
                    // timed on a cpu with cpufreq/scaling_governor set to "performance":
                    // https small (1.5k):  http: 4ms for 10, khttp: 16ms for 10, request: 32ms for 10
                    done();
                }
            }
        })
    })
})
