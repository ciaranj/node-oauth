/*
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

var Promise = require("bluebird");
var _OAuth = require("./oauth").OAuth;

/**
 * Constructor for Promisified OAuth1 object. Creates the original
 * class and delegates most methods to it.
 *
 * @class OAuthPromise
 */
var OAuth = function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._oa = new _OAuth(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders);
  this._oa.prototype = Promise.promisifyAll(_OAuth.prototype, { multiArgs: true });
};

/**
 * Delegates the method in the Promisified OAuth1 class to the
 * original class.
 * @private
 */
function delegate(methodName) {
  OAuth.prototype[methodName] = function() {
    return this._oa[methodName].apply(this._oa, arguments);
  };
}

/**
 * Delegates the asynchronous method in the Promisified OAuth1 class to
 * the original class (these method names end with "Async").
 * @private
 */
function asyncDelegate(methodName) {
  OAuth.prototype[methodName] = function() {
    return this._oa[methodName + "Async"].apply(this._oa, arguments);
  };
}

var delegatedPromiseMethods = [
  /**
   * @method delete
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#delete
   * @return {Promise}
   */
  "delete",

  /**
   * @method get
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#get
   * @return {Promise}
   */
  "get",

  /**
   * @method getOAuthAccessToken
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#getOAuthAccessToken
   * @return {Promise}
   */
  "getOAuthAccessToken",

  /**
   * @method getOAuthRequestToken
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#getOAuthRequestToken
   * @return {Promise}
   */
  "getOAuthRequestToken",

  /**
   * @method post
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#post
   * @return {Promise}
   */
  "post",

  /**
   * @method put
   * @memberof OAuthPromise
   * @instance
   * @see OAuth#put
   * @return {Promise}
   */
  "put"
];

delegatedPromiseMethods.forEach(asyncDelegate);

/**
 * delegates PromiseOAuth.methodName to OAuth.methodName
 * @private
 */
var delegatedMethods = [
  /**
   * @instance
   * @method authHeader
   * @memberof OAuthPromise
   * @see OAuth#authHeader
   */
  "authHeader",

  /**
   * @instance
   * @method getProtectedResource
   * @memberof OAuthPromise
   * @see OAuth#getProtectedResource
   */
  "getProtectedResource",

  /**
   * @instance
   * @method setClientOptions
   * @memberof OAuthPromise
   * @see OAuth#setClientOptions
   */
  "setClientOptions",

  /**
   * @instance
   * @method signUrl
   * @memberof OAuthPromise
   * @see OAuth#signUrl
   */
  "signUrl",

  // Required for testing
  "_buildAuthorizationHeaders",
  "_createSignature",
  "_createSignatureBase",
  "_encodeData",
  "_getNonce",
  "_getSignature",
  "_getTimestamp",
  "_isParameterNameAnOAuthParameter",
  "_makeArrayOfArgumentsHash",
  "_normaliseRequestParams",
  "_normalizeUrl",
  "_performSecureRequest",
  "_prepareParameters",
  "_sortRequestParams"
];

delegatedMethods.forEach(delegate);

exports.OAuth = OAuth;
