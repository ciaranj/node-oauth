/**
 * node-oauth-libre is a Node.js library for OAuth
 *
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

var Promise = require('bluebird');
var _OAuth2 = require('./oauth2').OAuth2;

var OAuth2 = function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._oa = new _OAuth2(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders);
  this._oa.prototype = Promise.promisifyAll(_OAuth2.prototype, { multiArgs: true });
};

// Promisfied public API for OAuth2
OAuth2.prototype.getOAuthAccessToken = function() {
  return this._oa.getOAuthAccessTokenAsync.apply(this._oa, arguments);
};

OAuth2.prototype.get = function() {
  return this._oa.getAsync.apply(this._oa, arguments).then(function(res) {
    return res[0];
  });
};

// delegates PromiseOAuth2.methodName to OAuth2.methodName
var delegatedMethods = [
  'buildAuthHeader',
  'getAuthorizeUrl',
  'setAuthMethod',
  'useAuthorizationHeaderforGET',

  // Required for testing
  '_executeRequest',
  '_request'
];

delegatedMethods.forEach(delegate);

function delegate(methodName) {
  OAuth2.prototype[methodName] = function() {
    return this._oa[methodName].apply(this._oa, arguments);
  };
}

exports.OAuth2 = OAuth2;
