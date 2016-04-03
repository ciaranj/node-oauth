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
  return this._oa.getAsync.apply(this._oa, arguments);
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
