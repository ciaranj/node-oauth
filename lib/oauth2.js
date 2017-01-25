/*
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2010-2012 Ciaran Jessup
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

var querystring = require("querystring");
var crypto = require("crypto");
var https = require("https");
var http = require("http");
var URL = require("url");
var OAuthUtils = require("./_utils");
var Buffer = require("buffer").Buffer;
var util = require("util");

var EventEmitter = require("events").EventEmitter;

/**
 * OAuth 2.0 client
 * @class
 * @param {string} clientId The id of the client
 * @param {string} clientSecret The secret key of the client
 * @param {string} baseSite URL of the OAuth endpoint
 * @param {string} authorizePath URL for token authorization endpoint
 * @param {string} accessTokenPath URL for access token endpoint
 * @param {Object} customHeaders HTTP headers for every request
 */
exports.OAuth2 = function (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  EventEmitter.call(this);
  /** @protected */
  this._clientId = clientId;
  /** @protected */
  this._clientSecret = clientSecret;
  /** @protected */
  this._baseSite = baseSite;

  /**
   * @protected
   * @default "/oauth/authorize"
   */
  this._authorizeUrl = authorizePath || "/oauth/authorize";

  /**
   * @protected
   * @default "/oauth/access_token"
   */
  this._accessTokenUrl = accessTokenPath || "/oauth/access_token";

  /**
   * The name of the access token in the query string
   * @protected
   * @default "access_token"
   */
  this._accessTokenName = "access_token";

  /**
   * The authorization method to use
   * @protected
   * @default "Bearer"
   */
  this._authMethod = "Bearer";

  /**
   * Custom headers for each request
   * @protected
   * @default {}
   */
  this._customHeaders = customHeaders || {};

  /**
   * Whether or not to use the authorization header for a GET request
   * @protected
   * @default false
   */
  this._useAuthorizationHeaderForGET = false;
};

/**
 * inherits from EventEmitter should use extends for future versions
 */
util.inherits(exports.OAuth2, EventEmitter);

/**
 * This 'hack' method is required for sites that don't use
 * 'access_token' as the name of the access token (for requests). It
 * isn't clear what the correct value should be at the moment, so
 * allowing for specific (temporary?) override for now.
 *
 * @param {string} name
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7
 */
exports.OAuth2.prototype.setAccessTokenName = function (name) {
  this._accessTokenName = name;
};

/**
 * Sets the authorization method for Authorization header.
 * e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
 *
 * @param {string} authMethod
 */
exports.OAuth2.prototype.setAuthMethod = function (authMethod) {
  this._authMethod = authMethod;
};

/**
 * If you use the OAuth2 exposed 'get' method (and don't construct
 * your own _request call) this will specify whether to use an
 * 'Authorize' header instead of passing the access_token as a query
 * parameter
 *
 * @param {boolean} useIt
 */
exports.OAuth2.prototype.useAuthorizationHeaderforGET = function (useIt) {
  this._useAuthorizationHeaderForGET = useIt;
};

/**
 * Returns the access token url constructed from the baseSite and
 * accessTokenUrl.
 *
 * @return {string}
 */
exports.OAuth2.prototype._getAccessTokenUrl = function () {
  return this._baseSite + this._accessTokenUrl; /* + "?" + querystring.stringify(params); */
};

/**
 * Build the authorization header. In particular, build the part after the colon.
 * e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
 *
 * @param {string} token
 * @return {string}
 */
exports.OAuth2.prototype.buildAuthHeader = function (token) {
  return this._authMethod + " " + token;
};

/**
 * Chooses the HTTP or HTTPS library. Assumes HTTPS by default.
 *
 * @param {url} parsedUrl Protocol of this URL begins with "http:" or "https:", if it does not assumes HTTPS protocol.
 *
 * @return {Object} http or https library
 */
exports.OAuth2.prototype._chooseHttpLibrary = function (parsedUrl) {
  var httpLibrary = https;
  // As this is OAUth2, we *assume* https unless told explicitly otherwise.
  if (parsedUrl.protocol != "https:") {
    httpLibrary = http;
  }
  return httpLibrary;
};

/**
 * Callback when the request has completed
 *
 * @callback OAuth2~executeRequestCallback
 * @param {object|null} data
 * @param {number} data.statusCode The HTTP Status Code
 * @param {any} data.data The data from the response
 * @param {any} result The data from the response
 * @param {Response} response The HTTP response object
 */

/**
 * Executes an HTTP (or HTTPS) request. If the User-Agent HTTP header
 * is not provided in _customHeaders or in the headers parameter, the
 * default is "Node-oauth".
 *
 * @fires OAuth2#request:before
 * @fires OAuth2#request:after
 *
 * @param {string} method The HTTP method to use (GET, POST, PUT, HEAD)
 * @param {string} url The URL to execute the request against
 * @param {Object} headers The headers to send as part of this request
 * @param {Buffer|null} postBody The body to send if this is a POST request
 * @param {string} accessToken The access token
 * @param {OAuth2~executeRequestCallback} callback The callback function to call when the request has been completed
 */
exports.OAuth2.prototype._request = function oauth2Request(method, url, headers, postBody, accessToken, callback) {
  var key;
  var instance = this;
  var parsedUrl = URL.parse(url, true);
  if (parsedUrl.protocol === "https:" && !parsedUrl.port) {
    parsedUrl.port = 443;
  }

  var httpLibrary = this._chooseHttpLibrary(parsedUrl);

  var realHeaders = {};
  for (key in this._customHeaders) {
    if ({}.hasOwnProperty.call(this._customHeaders, key)) {
      realHeaders[key] = this._customHeaders[key];
    }
  }
  if (headers) {
    for (key in headers) {
      if ({}.hasOwnProperty.call(headers, key)) {
        realHeaders[key] = headers[key];
      }
    }
  }
  realHeaders["Host"] = parsedUrl.host;

  if (!realHeaders["User-Agent"]) {
    realHeaders["User-Agent"] = "Node-oauth";
  }

  if (postBody) {
    if (Buffer.isBuffer(postBody)) {
      realHeaders["Content-Length"] = postBody.length;
    } else {
      realHeaders["Content-Length"] = Buffer.byteLength(postBody);
    }
  } else {
    realHeaders["Content-Length"] = 0;
  }

  if (accessToken && !("Authorization" in realHeaders)) {
    if (!parsedUrl.query) {
      parsedUrl.query = {};
    }
    parsedUrl.query[this._accessTokenName] = accessToken;
  }

  var queryStr = querystring.stringify(parsedUrl.query);
  if (queryStr) {
    queryStr = "?" + queryStr;
  }
  var options = {
    host: parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname + queryStr,
    method: method,
    headers: realHeaders
  };
  
  /**
   * Prepare response callback for _executeRequest method and emit then OAuth2#request:after event.
   * @method wrapRequestCallbackToEmit
   * @param  {object} oauth - This
   * @param  {OAuth2~executeRequestCallback} requestCallback - callback form original request method
   * @return {OAuth2~executeRequestCallback} Function to be executed after request execution
   */
  function wrapRequestCallbackToEmit(oauth, requestCallback) {
    /**
     * Event raised after a request is executed.
     *
     * @event OAuth2#request:after
     * @type {function}
     * @param {object} response - Contains information about response of the request
     * @param {object} result - You can access to data returned from the request if there"s data.
     */
    return function () {
      var response, result;
      if (arguments.length > 1) {
        response = arguments[2]; // status code
        result = arguments[1]; // result
        oauth.emit("request:after", response, result);
        requestCallback(arguments[0], arguments[1], arguments[2]); // null error , result data, status code
      }else {
        response = arguments[0].statusCode;
        result = arguments[0].data;
        oauth.emit("request:after", response, result);
        requestCallback(arguments[0]); // error or response formated object
      }
    };
  }
  
  var executed = false;
  var listenersCount = EventEmitter.listenerCount(this, "request:before");
  if (listenersCount > 0) {
    /**
     * This blocking callback allow to indicate when to continue when request execution, this is indicated
     * by shouldExecute param.
     *
     * @callback requestBeforeCallback
     * @param {object} optionsModified - Object contianing modified request optionsModified.
     * @param {object} postBodyModified - Object contianing postBody request with new values.
     * @param {boolean} shouldExecute - Indicates if request must be executes just before this event handling.
     */

    /**
     * Event raised before a request is executed, pass a blocking flag to prevent
     * many reques executions at same time.
     *
     * @event OAuth2#request:before
     * @type {function}
     * @param {object} options - Contains information of request like, host, post, path, method, and headers object
     * @param {object} postBody - Contains information of request body parameters
     * @param {requestBeforeCallback} done - Blocking function to pass modified request properties back
     */
    instance.emit("request:before", options, postBody, function (optionsModified, postBodyModified, shouldExecute) {
      shouldExecute = shouldExecute || false;
      if (!executed && shouldExecute) {
        executed = true;
        instance._executeRequest(httpLibrary, optionsModified, postBodyModified, wrapRequestCallbackToEmit(instance, callback));
      } else if (shouldExecute) {
        throw new Exception("request must be called just once");
      }
    });
  } else {
    instance._executeRequest(httpLibrary, options, postBody, wrapRequestCallbackToEmit(instance, callback));
  }
};

/**
 * Executes an OAuth-authenticated HTTP or HTTPS request. Allows for
 * some hosts that close connections early or that send no
 * Content-Length header.
 *
 * Sends the postBody if the request method is a POST, PUT, or PATCH.
 *
 * @param {Object} httpLibrary The HTTP or HTTPS library to use to execute the request
 * @param {Object} options The options for the request being made
 * @param {string} options.method
 * @param {Buffer|null} postBody
 * @param {OAuth2~executeRequestCallback} callback
 *
 * @see OAuthUtils#isAnEarlyCloseHost
 */
exports.OAuth2.prototype._executeRequest = function (httpLibrary, options, postBody, callback) {
  // Some hosts *cough* google appear to close the connection early / send no content-length header
  // allow this behaviour.
  var allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(options.host);
  var callbackCalled = false;
  function passBackControl (response, result) {
    if (!callbackCalled) {
      callbackCalled = true;
      if (!(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode !== 301) && (response.statusCode !== 302)) {
        callback({ statusCode: response.statusCode, data: result });
      } else {
        callback(null, result, response);
      }
    }
  }

  var result = "";

  var request = httpLibrary.request(options);
  request.on("response", function (response) {
    response.on("data", function (chunk) {
      result += chunk;
    });
    response.on("close", function (err) {
      if (allowEarlyClose) {
        passBackControl(response, result);
      }
    });
    response.addListener("end", function () {
      passBackControl(response, result);
    });
  });
  request.on("error", function (e) {
    callbackCalled = true;
    callback(e);
  });

  if ((options.method === "POST" || options.method === "PUT" || options.method === "PATCH") && postBody) {
    request.write(postBody);
  }
  request.end();
};

/**
 * Returns the fully-qualified authorization url including query
 * string parameters.
 *
 * @param params Query string parameters
 */
exports.OAuth2.prototype.getAuthorizeUrl = function (params) {
  var mergedParams = params || {};
  mergedParams["client_id"] = this._clientId;
  return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(mergedParams);
};

/**
 * Returns the authorization header
 *
 * @return {string}
 */
exports.OAuth2.prototype._getAuthorizationHeader = function () {
  var clientIdAndSecret = this._clientId + ":" + this._clientSecret;
  var clientInfoAsBase64 = new Buffer(clientIdAndSecret).toString("base64");
  return "Basic " + clientInfoAsBase64.toString();
};

/**
 * @callback OAuth2~accessTokenCallback
 * @param {Error|null} error If there was an error in the request
 * @param {string} accessToken The OAuth access token
 * @param {string} refreshToken The OAuth refresh token
 * @param {any} results The data from the HTTP response
 */

/**
 * Gets the OAuth access token from the OAuth2.0 endpoint. Sends a
 * POST request to the access token url and on success or error, calls
 * the provided callback.
 *
 * @param {string} code The code to send
 * @param {Object} params The OAuth parameters to send
 * @param {string} [params.grant_type] The grant type to use with OAuth, the two options are 'refresh_token' or 'code'.
 * @param {OAuth2~accessTokenCallback} callback
 */
exports.OAuth2.prototype.getOAuthAccessToken = function (code, params, callback) {
  var params = params || {};
  params["client_id"] = this._clientId;
  params["client_secret"] = this._clientSecret;
  var codeParam = (params.grant_type === "refresh_token") ? "refresh_token" : "code";
  params[codeParam] = code;

  var postData = querystring.stringify(params);

  var postHeaders = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": this._getAuthorizationHeader()
  };

  this._request("POST", this._getAccessTokenUrl(), postHeaders, postData, null, function (error, data, response) {
    if (error) {
      callback(error);
    } else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results = JSON.parse(data);
      } catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results = querystring.parse(data);
      }
      var accessToken = results["access_token"];
      var refresh_token = results["refresh_token"];
      delete results["refresh_token"];
      callback(null, accessToken, refresh_token, results); // callback results =-=
    }
  });
};

/**
 * @deprecated
 */
exports.OAuth2.prototype.getProtectedResource = function (url, accessToken, callback) {
  this._request("GET", url, {}, "", accessToken, callback);
};

/**
 * Executes an OAuth2-authenticated GET request to the url provided
 *
 * @param {string} url The URL to make a request to
 * @param {string} accessToken OAuth 2.0 Access Token
 * @param {OAuth2~executeRequestCallback} callback
 */
exports.OAuth2.prototype.get = function (url, accessToken, callback) {
  if (this._useAuthorizationHeaderForGET) {
    var headers = { "Authorization": this.buildAuthHeader(accessToken)};
    accessToken = null;
  } else {
    headers = {};
  }
  this._request("GET", url, headers, "", accessToken, callback);
};
