var Promise = require('bluebird');
var _OAuth = require('./oauth').OAuth;

var OAuth = function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._oa = new _OAuth(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders);
  this._oa.prototype = Promise.promisifyAll(_OAuth.prototype, { multiArgs: true });
};

// Promisifed public API for OAuth
var delegatedPromiseMethods = [
  'delete',
  'get',
  'getOAuthAccessToken',
  'getOAuthRequestToken',
  'post',
  'put',
  'signUrl'
];

delegatedPromiseMethods.forEach(asyncDelegate);

// delegates PromiseOAuth.methodName to OAuth.methodName
var delegatedMethods = [
  'authHeader',
  'getProtectedResource',
  'setClientOptions',

  // Required for testing
  '_buildAuthorizationHeaders',
  '_createSignature',
  '_createSignatureBase',
  '_encodeData',
  '_getNonce',
  '_getSignature',
  '_getTimestamp',
  '_isParameterNameAnOAuthParameter',
  '_makeArrayOfArgumentsHash',
  '_normaliseRequestParams',
  '_normalizeUrl',
  '_performSecureRequest',
  '_prepareParameters',
  '_sortRequestParams'
];

delegatedMethods.forEach(delegate);

function delegate(methodName) {
  OAuth.prototype[methodName] = function() {
    return this._oa[methodName].apply(this._oa, arguments);
  };
}

function asyncDelegate(methodName) {
  OAuth.prototype[methodName] = function() {
    return this._oa[methodName + 'Async'].apply(this._oa, arguments);
  };
}

exports.OAuth = OAuth;
