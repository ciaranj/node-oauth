/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2010-2012 Ciaran Jessup
 * Copyright (C) 2016 Rudolf Olah
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var vows = require("vows");
var assert = require("assert");
var DummyResponse= require("./shared").DummyResponse;
var DummyRequest= require("./shared").DummyRequest;
var https = require("https");
var OAuth2= require("../lib/oauth2-promise").OAuth2;
var url = require("url");

vows.describe("OAuth2-Promise").addBatch({
  "Given an OAuth2 instance with clientId and clientSecret, ": {
    topic: new OAuth2("clientId", "clientSecret"),
    "When dealing with the response from the OP": {
      "we should treat a 201 response as a success": function (oa) {
        var callbackCalled = false;
        var httpLibrary = {
          request: function () {
            return new DummyRequest(new DummyResponse(201));
          }
        };
        oa._executeRequest(httpLibrary, {}, null, function (err, result, response) {
          callbackCalled = true;
          assert.equal(err, null);
        });
        assert.ok(callbackCalled);
      },
      "we should treat a 200 response as a success": function (oa) {
        var callbackCalled = false;
        var httpLibrary = {
          request: function () {
            return new DummyRequest(new DummyResponse(200));
          }
        };
        oa._executeRequest(httpLibrary, {}, null, function (err, result, response) {
          callbackCalled = true;
          assert.equal(err, null);
        });
        assert.ok(callbackCalled);
      }
    },
    "When handling the access token response": {
      "we should correctly extract the token if received as form-data": function (oa) {
        oa._request = function (method, url, fo, bar, bleh, callback) {
          callback(null, "access_token=access&refresh_token=refresh");
        };
        oa.getOAuthAccessToken("", {}, function (error, accessToken, refreshToken) {
          assert.equal(accessToken, "access");
          assert.equal(refreshToken, "refresh");
        });
      },
      "we should not include access token in both querystring and headers (favours headers if specified)": function (oa) {
        oa._request = new OAuth2("clientId", "clientSecret")._request.bind(oa);
        oa._executeRequest = function (httpLibrary, options, post_body, callback) {
          callback(null, url.parse(options.path, true).query, options.headers);
        };

        oa._request("GET", "http://foo/", { "Authorization": "Bearer BadNews" }, null, "accessx",  function (error, query, headers) {
          assert.ok(!("access_token" in query), "access_token also in query");
          assert.ok("Authorization" in headers, "Authorization not in headers");
        });
      },
      "we should include access token in the querystring if no Authorization header present to override it": function (oa) {
        oa._request = new OAuth2("clientId", "clientSecret")._request.bind(oa);
        oa._executeRequest = function (httpLibrary, options, post_body, callback) {
          callback(null, url.parse(options.path, true).query, options.headers);
        };
        oa._request("GET", "http://foo/", {}, null, "access",  function (error, query, headers) {
          assert.ok("access_token" in query, "access_token not present in query");
          assert.ok(!("Authorization" in headers), "Authorization in headers");
        });
      },
      "we should correctly extract the token if received as a JSON literal": function (oa) {
        oa._request = function (method, url, headers, post_body, accessToken, callback) {
          callback(null, '{ "access_token": "access","refresh_token": "refresh" }');
        };
        oa.getOAuthAccessToken("", {}, function (error, accessToken, refreshToken) {
          assert.equal(accessToken, "access");
          assert.equal(refreshToken, "refresh");
        });
      },
      "we should return the received data to the calling method": function (oa) {
        oa._request = function (method, url, headers, post_body, accessToken, callback) {
          callback(null, '{ "access_token": "access","refresh_token": "refresh","extra_1":1, "extra_2": "foo" }');
        };
        oa.getOAuthAccessToken("", {}, function (error, accessToken, refreshToken, results) {
          assert.equal(accessToken, "access");
          assert.equal(refreshToken, "refresh");
          assert.isNotNull(results);
          assert.equal(results.extra_1, 1);
          assert.equal(results.extra_2, "foo");
        });
      }
    },
    "When no grant_type parameter is specified": {
      "we should pass the value of the code argument as the code parameter": function (oa) {
        oa._request = function (method, url, headers, post_body, accessToken, callback) {
          assert.isTrue(post_body.indexOf("code=xsds23") != -1);
        };
        oa.getOAuthAccessToken("xsds23", {});
      }
    },
    "When an invalid grant_type parameter is specified": {
      "we should pass the value of the code argument as the code parameter": function (oa) {
        oa._request = function (method, url, headers, post_body, accessToken, callback) {
          assert.isTrue(post_body.indexOf("code=xsds23") !== -1);
        };
        oa.getOAuthAccessToken("xsds23", {grant_type: "refresh_toucan" });
      }
    },
    "When a grant_type parameter of value 'refresh_token' is specified": {
      "we should pass the value of the code argument as the refresh_token parameter, should pass a grant_type parameter, but shouldn\"t pass a code parameter": function (oa) {
        oa._request = function (method, url, headers, post_body, accessToken, callback) {
          assert.isTrue(post_body.indexOf("refresh_token=sdsds2") !== -1);
          assert.isTrue(post_body.indexOf("grant_type=refresh_token") !== -1);
          assert.isTrue(post_body.indexOf("code=") === -1);
        };
        oa.getOAuthAccessToken("sdsds2", {grant_type: "refresh_token" });
      }
    },
    "When we use the authorization header": {
      "and call get with the default authorization method": {
        "we should pass the authorization header with Bearer method and value of the access_token, _request should be passed a null access_token": function (oa) {
          oa._request = function (method, url, headers, post_body, accessToken, callback) {
            assert.equal(headers["Authorization"], "Bearer abcd5");
            assert.isNull(accessToken);
          };
          oa.useAuthorizationHeaderforGET(true);
          oa.get("", "abcd5");
        }
      },
      "and call get with the authorization method set to Basic": {
        "we should pass the authorization header with Basic method and value of the access_token, _request should be passed a null access_token": function (oa) {
          oa._request = function (method, url, headers, post_body, accessToken, callback) {
            assert.equal(headers["Authorization"], "Basic cdg2");
            assert.isNull(accessToken);
          };
          oa.useAuthorizationHeaderforGET(true);
          oa.setAuthMethod("Basic");
          oa.get("", "cdg2");
        }
      }
    },
    "When we do not use the authorization header": {
      "and call get": {
        "we should pass NOT provide an authorization header and the access_token should be being passed to _request": function (oa) {
          oa._request = function (method, url, headers, post_body, accessToken, callback) {
            assert.isUndefined(headers["Authorization"]);
            assert.equal(accessToken, "abcd5");
          };
          oa.useAuthorizationHeaderforGET(false);
          oa.get("", "abcd5");
        }
      }
    }
  },
  "Given an OAuth2 instance with clientId, clientSecret and customHeaders": {
    topic: new OAuth2("clientId", "clientSecret", null, null, null,
                      { "SomeHeader": "123" }),
    "When GETing": {
      "we should see the custom headers mixed into headers property in options passed to http-library": function (oa) {
        oa._executeRequest = function (httpLibrary, options, callback) {
          assert.equal(options.headers["SomeHeader"], "123");
        };
        oa.get("", {});
      },
    }
  },
  "Given an OAuth2 instance with a clientId and clientSecret": {
    topic: new OAuth2("clientId", "clientSecret"),
    "When POSTing": {
      "we should see a given string being sent to the request": function (oa) {
        var bodyWritten = false;
        oa._oa._chooseHttpLibrary = function () {
          return {
            request: function (options) {
              assert.equal(options.headers["Content-Type"], "text/plain");
              assert.equal(options.headers["Content-Length"], 26);
              assert.equal(options.method, "POST");
              return  {
                end: function () {},
                on: function () {},
                write: function (body) {
                  bodyWritten = true;
                  assert.isNotNull(body);
                  assert.equal(body, "THIS_IS_A_POST_BODY_STRING");
                }
              };
            }
          };
        }
        oa._request("POST", "", { "Content-Type": "text/plain" }, "THIS_IS_A_POST_BODY_STRING");
        assert.ok(bodyWritten);
      },
      "we should see a given buffer being sent to the request": function (oa) {
        var bodyWritten = false;
        oa._oa._chooseHttpLibrary = function () {
          return {
            request: function (options) {
              assert.equal(options.headers["Content-Type"], "application/octet-stream");
              assert.equal(options.headers["Content-Length"], 4);
              assert.equal(options.method, "POST");
              return  {
                end: function () {},
                on: function () {},
                write: function (body) {
                  bodyWritten = true;
                  assert.isNotNull(body);
                  assert.equal(4, body.length);
                }
              };
            }
          };
        }
        oa._request("POST", "", { "Content-Type": "application/octet-stream" }, new Buffer([1,2,3,4]));
        assert.ok(bodyWritten);
      }
    },
    "When PUTing": {
      "we should see a given string being sent to the request": function (oa) {
        var bodyWritten = false;
        oa._oa._chooseHttpLibrary = function () {
          return {
            request: function (options) {
              assert.equal(options.headers["Content-Type"], "text/plain");
              assert.equal(options.headers["Content-Length"], 25);
              assert.equal(options.method, "PUT");
              return  {
                end: function () {},
                on: function () {},
                write: function (body) {
                  bodyWritten = true;
                  assert.isNotNull(body);
                  assert.equal(body, "THIS_IS_A_PUT_BODY_STRING");
                }
              };
            }
          };
        }
        oa._request("PUT", "", { "Content-Type": "text/plain" }, "THIS_IS_A_PUT_BODY_STRING");
        assert.ok(bodyWritten);
      },
      "we should see a given buffer being sent to the request": function (oa) {
        var bodyWritten = false;
        oa._oa._chooseHttpLibrary = function () {
          return {
            request: function (options) {
              assert.equal(options.headers["Content-Type"], "application/octet-stream");
              assert.equal(options.headers["Content-Length"], 4);
              assert.equal(options.method, "PUT");
              return  {
                end: function () {},
                on: function () {},
                write: function (body) {
                  bodyWritten = true;
                  assert.isNotNull(body);
                  assert.equal(4, body.length)
                }
              };
            }
          };
        }
        oa._request("PUT", "", { "Content-Type": "application/octet-stream" }, new Buffer([1,2,3,4]));
        assert.ok(bodyWritten);
      }
    }
  },
  "When the user passes in the User-Agent in customHeaders": {
    topic: new OAuth2("clientId", "clientSecret", null, null, null,
                      { "User-Agent": "123Agent" }),
    "When calling get": {
      "we should see the User-Agent mixed into headers property in options passed to http-library": function (oa) {
        oa._executeRequest = function (httpLibrary, options, callback) {
          assert.equal(options.headers["User-Agent"], "123Agent");
        };
        oa.get("", {});
      }
    }
  },
  "When the user does not pass in a User-Agent in customHeaders": {
    topic: new OAuth2("clientId", "clientSecret", null, null, null,
                      null),
    "When calling get": {
      "we should see the default User-Agent mixed into headers property in options passed to http-library": function (oa) {
        oa._executeRequest = function (httpLibrary, options, callback) {
          assert.equal(options.headers["User-Agent"], "Node-oauth");
        };
        oa.get("", {});
      }
    }
  }
}).export(module);
