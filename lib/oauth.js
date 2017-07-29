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

var crypto= require('crypto'),
    sha1= require('./sha1'),
    http= require('http'),
    https= require('https'),
    URL= require('url'),
    querystring= require('querystring'),
    OAuthUtils= require('./_utils');

/**
 * OAuth 1.0 client
 * @class
 * @param {string} requestUrl
 * @param {string} accessUrl
 * @param {string} consumerKey
 * @param {string} consumerSecret
 * @param {string} version
 * @param {string} authorize_callback default is "oob"
 * @param {string} signatureMethod can be PLAINTEXT, HMAC-SHA1 or RSA-SHA1
 * @param {number} nonceSize default is 32
 * @param {Object} customHeaders Default headers are set for Accept, Connection, User-Agent
 */
exports.OAuth= function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._defaultContentType = 'application/x-www-form-urlencoded';
  if (customHeaders && customHeaders['Content-Type']) {
      this._defaultContentType = customHeaders['Content-Type'];
      delete customHeaders['Content-Type'];
  }
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
};

/**
 * OAuth 1.0 Echo client
 * @class
 * @augments OAuth
 * @param realm
 * @param verify_credentials
 * @param {string} consumerKey
 * @param {string} consumerSecret
 * @param {string} version
 * @param {string} signatureMethod can be PLAINTEXT, HMAC-SHA1 or RSA-SHA1
 * @param {number} nonceSize default is 32
 * @param {Object} customHeaders Default headers are set for Accept, Connection, User-Agent
 */
exports.OAuthEcho= function(realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
}

exports.OAuthEcho.prototype = exports.OAuth.prototype;

/**
 * Returns the current time as a UNIX timestamp
 *
 * @return {number}
 */
exports.OAuth.prototype._getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
}

/**
 * Encodes the data given by replacing characters "!'()*" with their
 * encoded equivalents and returning the result of encodeURIComponent.
 *
 * @param {string} toEncode
 * @return {string}
 * @see https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
 */
exports.OAuth.prototype._encodeData= function(toEncode){
 if( toEncode == null || toEncode == "" ) return ""
 else {
    var result= encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
 }
}

/**
 * Decodes the data provided by replacing "+" plus character with
 * spaces and returning the result of decodeURIComponent.
 *
 * @param {string} toDecode
 * @return {string}
 * @see https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
 */
exports.OAuth.prototype._decodeData= function(toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
}

/**
 * Returns the signature
 *
 * @param {string} method HTTP method
 * @param {string} url
 * @param {Object} parameters Query string parameters
 * @param {string} tokenSecret
 */
exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
  var signatureBase= this._createSignatureBase(method, url, parameters);
  return this._createSignature( signatureBase, tokenSecret );
}

/**
 * Normalizes the URL by accounting for custom HTTP and HTTPS ports.
 *
 * @param {string} url
 * @return {string}
 */
exports.OAuth.prototype._normalizeUrl= function(url) {
  var parsedUrl= URL.parse(url, true)
   var port ="";
   if( parsedUrl.port ) {
     if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
         (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
           port= ":" + parsedUrl.port;
         }
   }

  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";

  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
}

/**
 * Is the parameter considered an OAuth parameter.
 *
 * @param {string} parameter
 * @return {boolean} true if the parameter starts with "oauth_"
 */
exports.OAuth.prototype._isParameterNameAnOAuthParameter= function(parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
};

/**
 * Build the OAuth request authorization header
 *
 * @param {Object} orderedParameters
 * @return {Object} the authorization header
 */
exports.OAuth.prototype._buildAuthorizationHeaders= function(orderedParameters) {
  var authHeader="OAuth ";
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\""+ this._oauthParameterSeperator;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
  return authHeader;
}

/**
 * Takes an object literal that represents the arguments, and returns
 * an array of argument/value pairs.
 *
 * @param {Object} argumentsHash
 * @return {Array}
 */
exports.OAuth.prototype._makeArrayOfArgumentsHash= function(argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {
    if (argumentsHash.hasOwnProperty(key)) {
       var value= argumentsHash[key];
       if( Array.isArray(value) ) {
         for(var i=0;i<value.length;i++) {
           argument_pairs[argument_pairs.length]= [key, value[i]];
         }
       }
       else {
         argument_pairs[argument_pairs.length]= [key, value];
       }
    }
  }
  return argument_pairs;
}

/**
 * Sorts the encoded key value pairs by encoded name, then encoded
 * value
 *
 * @param {Array} argument_pairs
 * @param {Array}
 */
exports.OAuth.prototype._sortRequestParams= function(argument_pairs) {
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1;
      }
      else return a[0] < b[0] ? -1 : 1;
  });

  return argument_pairs;
}

/**
 * Normalizes the request parameters.
 *
 * @param {Object} args
 * @return {Object}
 */
exports.OAuth.prototype._normaliseRequestParams= function(args) {
  var argument_pairs= this._makeArrayOfArgumentsHash(args);
  // First encode them #3.4.1.3.2 .1
  for(var i=0;i<argument_pairs.length;i++) {
    argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
    argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
  }

  // Then sort them #3.4.1.3.2 .2
  argument_pairs= this._sortRequestParams( argument_pairs );

  // Then concatenate together #3.4.1.3.2 .3 & .4
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= argument_pairs[i][0];
      args+= "="
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }
  return args;
}

/**
 * Creates the base signature
 *
 * @param {string} method HTTP Method
 * @param {string} url
 * @param {string} parameters Query string parameters
 * @return {string}
 */
exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}

/**
 * Creates the signature from the base signature and token secret
 *
 * @param {string} signatureBase
 * @param {string} tokenSecret
 * @return {string} The hashed version of the signature
 * @see OAuth#_createSignatureBase
 */
exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret );
   // consumerSecret is already encoded
   var key= this._consumerSecret + "&" + tokenSecret;

   var hash= ""
   if( this._signatureMethod == "PLAINTEXT" ) {
     hash= key;
   }
   else if (this._signatureMethod == "RSA-SHA1") {
     key = this._privateKey || "";
     hash= crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
   }
   else {
       if( crypto.Hmac ) {
         hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
       }
       else {
         hash= sha1.hmacsha1(key, signatureBase);
       }
   }
   return hash;
}

/**
 * The characters that can be used in the nonce
 */
exports.OAuth.prototype.NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
              'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
              'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
              'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
              '4','5','6','7','8','9'];

/**
 * Generates a new nonce with the size of nonceSize
 *
 * @param {number} nonceSize
 * @return {string}
 */
exports.OAuth.prototype._getNonce= function(nonceSize) {
   var result = [];
   var chars= this.NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;

   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
}

/**
 * Creates the OAuth client
 */
exports.OAuth.prototype._createClient= function( port, hostname, method, path, headers, sslEnabled ) {
  var options = {
    host: hostname,
    port: port,
    path: path,
    method: method,
    headers: headers
  };
  var httpModel;
  if( sslEnabled ) {
    httpModel= https;
  } else {
    httpModel= http;
  }
  
  for (var k in this._httpOptions) {
    options[k] = this._httpOptions[k];
  }

  return httpModel.request(options);
}

/**
 * Sets the HTTP (or HTTPS) options for requests
 *
 * @see for HTTPS options: https://nodejs.org/api/https.html#https_https_request_options_callback
 * @see for HTTP options: https://nodejs.org/api/net.html#net_socket_connect_options_connectlistener
 */
exports.OAuth.prototype.setHttpOptions = function(options) {
  this._httpOptions = options;
}

exports.OAuth.prototype._prepareParameters= function( oauth_token, oauth_token_secret, method, url, extra_params ) {
  var oauthParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(this._nonceSize),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };

  if( oauth_token ) {
    oauthParameters["oauth_token"]= oauth_token;
  }

  var sig;
  if( this._isEcho ) {
    sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }
  else {
    if( extra_params ) {
      for( var key in extra_params ) {
        if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
      }
    }
    var parsedUrl= URL.parse( url, false );

    if( parsedUrl.query ) {
      var key2;
      var extraParameters= querystring.parse(parsedUrl.query);
      for(var key in extraParameters ) {
        var value= extraParameters[key];
          if( typeof value == "object" ){
            // TODO: This probably should be recursive
            for(key2 in value){
              oauthParameters[key + "[" + key2 + "]"] = value[key2];
            }
          } else {
            oauthParameters[key]= value;
          }
        }
    }

    sig = this._getSignature( method,  url,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }

  var orderedParameters= this._sortRequestParams( this._makeArrayOfArgumentsHash(oauthParameters) );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  return orderedParameters;
}

/**
 * @callback requestCallback
 * @memberof OAuth
 * @param error
 * @param data
 * @param response
 */

/**
 * Peforms an HTTP or HTTPS request
 *
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {string} method
 * @param {string} url
 * @param {Object} extra_params
 * @param {Buffer} post_body
 * @param {string} post_content_type
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

  if( !post_content_type ) {
    post_content_type= this._defaultContentType;
  }
  var parsedUrl= URL.parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  var headers= {};
  var authorization = this._buildAuthorizationHeaders(orderedParameters);
  if ( this._isEcho ) {
    headers["X-Verify-Credentials-Authorization"]= authorization;
  }
  else {
    headers["Authorization"]= authorization;
  }

  headers["Host"] = parsedUrl.host

  for( var key in this._headers ) {
    if (this._headers.hasOwnProperty(key)) {
      headers[key]= this._headers[key];
    }
  }

  // Filter out any passed extra_params that are really to do with OAuth
  for(var key in extra_params) {
    if( this._isParameterNameAnOAuthParameter( key ) ) {
      delete extra_params[key];
    }
  }

  if( (method == "POST" || method == "PUT" || method == "PATCH")  && ( post_body == null && extra_params != null) ) {
    // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
    post_body= querystring.stringify(extra_params)
                       .replace(/\!/g, "%21")
                       .replace(/\'/g, "%27")
                       .replace(/\(/g, "%28")
                       .replace(/\)/g, "%29")
                       .replace(/\*/g, "%2A");
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          headers["Content-length"]= post_body.length;
      } else {
          headers["Content-length"]= Buffer.byteLength(post_body);
      }
  } else {
      headers["Content-length"]= 0;
  }

  headers["Content-Type"]= post_content_type;

  var path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
  if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
  else path= parsedUrl.pathname;

  var request;
  if( parsedUrl.protocol == "https:" ) {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
  }
  else {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
  }

  var clientOptions = this._clientOptions;
  if( callback ) {
    var data="";
    var self= this;

    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost( parsedUrl.hostname );
    var callbackCalled= false;
    var passBackControl = function( response ) {
      if(!callbackCalled) {
        callbackCalled= true;
        if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
          callback(null, data, response);
        } else {
          // Follow 301 or 302 redirects with Location HTTP header
          if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
            self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type,  callback);
          }
          else {
            callback({ statusCode: response.statusCode, data: data }, data, response);
          }
        }
      }
    }

    request.on('response', function (response) {
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        data+=chunk;
      });
      response.on('end', function () {
        passBackControl( response );
      });
      response.on('close', function () {
        if( allowEarlyClose ) {
          passBackControl( response );
        }
      });
    });

    request.on("error", function(err) {
      if(!callbackCalled) {
        callbackCalled= true;
        callback( err )
      }
    });

    if( (method == "POST" || method =="PUT" || method == "PATCH") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    request.end();
  }
  else {
    if( (method == "POST" || method =="PUT" || method == "PATCH") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    return request;
  }

  return;
}

/**
 * Sets the HTTP client options
 *
 * @param {Object} options
 */
exports.OAuth.prototype.setClientOptions= function(options) {
  var key,
      mergedOptions= {},
      hasOwnProperty= Object.prototype.hasOwnProperty;

  for( key in this._defaultClientOptions ) {
    if( !hasOwnProperty.call(options, key) ) {
      mergedOptions[key]= this._defaultClientOptions[key];
    } else {
      mergedOptions[key]= options[key];
    }
  }

  this._clientOptions= mergedOptions;
};
exports.OAuth.prototype.setDefaultContentType= function(contentType) {
  this._defaultContentType = contentType;
};

/**
 * Performs a request to retrieve the OAuth Access Token
 *
 * @param {string} oauth_token
 * @param {string} oauth_token_secret
 * @param {string} oauth_verifier
 * @param {OAuth.requestCallback} callback
 * @param {Object} [extraParams] Extra parameters to send with the request
 */
exports.OAuth.prototype.getOAuthAccessToken= function(oauth_token, oauth_token_secret, oauth_verifier, callback, extraParams) {
  var extraParams = extraParams || {};
  if( typeof oauth_verifier == "function" ) {
    callback= oauth_verifier;
  } else {
    extraParams.oauth_verifier= oauth_verifier;
  }

   this._performSecureRequest( oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null, function(error, data, response) {
         if( error ) callback(error);
         else {
           var results= querystring.parse( data );
           var oauth_access_token= results["oauth_token"];
           delete results["oauth_token"];
           var oauth_access_token_secret= results["oauth_token_secret"];
           delete results["oauth_token_secret"];
           callback(null, oauth_access_token, oauth_access_token_secret, results );
         }
   })
}

/**
 * @deprecated
 */
exports.OAuth.prototype.getProtectedResource= function(url, method, oauth_token, oauth_token_secret, callback) {
  this._performSecureRequest( oauth_token, oauth_token_secret, method, url, null, "", null, callback );
}

/**
 * Executes an authenticated DELETE request
 *
 * @param {string} url
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype.delete= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback );
}

/**
 * Executes an authenticated GET request
 *
 * @param {string} url
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype.get= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "GET", url, null, "", null, callback );
}

/**
 * Executes an authenticated PUT or POST request
 *
 * @param {string} methpd
 * @param {string} url
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {Buffer} post_body
 * @param {string} post_content_type
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype._putOrPost= function(method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  var extra_params= null;
  if( typeof post_content_type == "function" ) {
    callback= post_content_type;
    post_content_type= null;
  }
  if ( typeof post_body != "string" && !Buffer.isBuffer(post_body) ) {
    post_content_type= "application/x-www-form-urlencoded"
    extra_params= post_body;
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback );
}

/**
 * Executes an authenticated PUT request
 *
 * @param {string} url
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {Buffer} post_body
 * @param {string} post_content_type
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype.put= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

/**
 * Executes an authenticated POST request
 *
 * @param {string} url
 * @param {string} oauth_token
 * @param {string} oauth_token_string
 * @param {Buffer} post_body
 * @param {string} post_content_type
 * @param {OAuth.requestCallback} callback
 */
exports.OAuth.prototype.post= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

/**
 * @callback oauthRequestTokenCallback
 * @memberof OAuth
 * @param error
 * @param token
 * @param tokenSecret
 * @param parsedQueryString
 */

/**
 * Gets a request token from the OAuth provider and passes that information back
 * to the calling code.
 *
 * The callback should expect a function of the following form:
 *
 * function(err, token, token_secret, parsedQueryString) {}
 *
 * This method has optional parameters so can be called in the following 2 ways:
 *
 * 1) Primary use case: Does a basic request with no extra parameters
 *  getOAuthRequestToken( callbackFunction )
 *
 * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
 *  getOAuthRequestToken( extraParams, callbackFunction )
 *
 * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
 * need to provide a requestTokenHttpMethod option when creating the client.
 *
 * @param {Object} extraParams
 * @param {OAuth.oauthRequestTokenCallback}
 */
exports.OAuth.prototype.getOAuthRequestToken= function( extraParams, callback ) {
   if( typeof extraParams == "function" ){
     callback = extraParams;
     extraParams = {};
   }
  // Callbacks are 1.0A related
  if( this._authorize_callback ) {
    extraParams["oauth_callback"]= this._authorize_callback;
  }
  this._performSecureRequest( null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function(error, data, response) {
    if( error ) callback(error);
    else {
      var results= querystring.parse(data);

      var oauth_token= results["oauth_token"];
      var oauth_token_secret= results["oauth_token_secret"];
      delete results["oauth_token"];
      delete results["oauth_token_secret"];
      callback(null, oauth_token, oauth_token_secret,  results );
    }
  });
}

/**
 * Returns the prepared ordered parameters
 *
 * @param oauthToken
 * @param oauthTokenSecret
 * @param method If this is undefined or null, default is 'GET'
 * @param url
 *
 * @return the result of calling _prepareParameters
 */
exports.OAuth.prototype._getOrderedParameters = function(oauthToken, oauthTokenSecret, method, url) {
  return this._prepareParameters(oauthToken, oauthTokenSecret, method ? method : 'GET', url, {});
};

/**
 * Signs the url
 *
 * @param url
 * @param oauthToken
 * @param oauthTokenSecret
 * @param method
 *
 * @see OAuth._getOrderedParameters
 * @see OAuth._encodeData
 */
exports.OAuth.prototype.signUrl = function(url, oauthToken, oauthTokenSecret, method) {

  var orderedParameters = this._getOrderedParameters(oauthToken, oauthTokenSecret, method, url);

  var parsedUrl = URL.parse( url, false );

  var query = "";
  for (var i = 0; i < orderedParameters.length; i++) {
    query += orderedParameters[i][0] + "=" +
      this._encodeData(orderedParameters[i][1]) + "&";
  }
  query = query.substring(0, query.length - 1);

  return parsedUrl.protocol + "//" +
    parsedUrl.host + parsedUrl.pathname + "?" +
    query;
};

/**
 * Returns the built authorization header
 *
 * @param url
 * @param oauthToken
 * @param oauthTokenSecret
 * @param method
 *
 * @see OAuth._getOrderedParameters
 * @see OAuth._buildAuthorizationHeaders
 */
exports.OAuth.prototype.authHeader = function(url, oauthToken, oauthTokenSecret, method) {
  var orderedParameters = this._getOrderedParameters(oauthToken, oauthTokenSecret, method, url);
  return this._buildAuthorizationHeaders(orderedParameters);
};
