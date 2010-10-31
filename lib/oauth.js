var crypto= require('crypto'),
    sha1= require('./sha1'),
    http= require('http'),
    URL= require('url'),
    querystring= require('querystring'); 

exports.OAuth= function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
};

exports.OAuth.prototype._getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
}

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

exports.OAuth.prototype._decodeData= function(toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
}

exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
  var signatureBase= this._createSignatureBase(method, url, parameters);
  return this._createSignature( signatureBase, tokenSecret );
}

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

// Is the parameter considered an OAuth parameter
exports.OAuth.prototype._isParameterNameAnOAuthParameter= function(parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
};

// build the OAuth request authorization header
exports.OAuth.prototype._buildAuthorizationHeaders= function(orderedParameters) {
  var authHeader="OAuth ";
  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\",";
     }
  }
  authHeader= authHeader.substring(0, authHeader.length-1);
  return authHeader;
}

// Takes a literal in, then returns a sorted array
exports.OAuth.prototype._sortRequestParams= function(argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {   
      argument_pairs[argument_pairs.length]= [key, argumentsHash[key]];
  }
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1; 
      }
      else return a[0] < b[0] ? -1 : 1;  
  });

  return argument_pairs;
}

exports.OAuth.prototype._normaliseRequestParams= function(arguments) {
  var argument_pairs= this._sortRequestParams( arguments );
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= this._encodeData( argument_pairs[i][0] );
      args+= "="
      args+= this._encodeData( argument_pairs[i][1] );
      if( i < argument_pairs.length-1 ) args+= "&";
  }     
  return args;
}

exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) ); 
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}

exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret ); 
   // consumerSecret is already encoded
   var key= this._consumerSecret + "&" + tokenSecret;

   var hash= ""
   if( this._signatureMethod == "PLAINTEXT" ) {
     hash= this._encodeData(key);
   }
   else {
     hash= sha1.HMACSHA1(key, signatureBase);
   }

   return hash;
}
exports.OAuth.prototype.NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
              'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
              'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
              'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
              '4','5','6','7','8','9'];

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

exports.OAuth.prototype._createClient= function( port, hostname, sshEnabled, credentials ) {
  return http.createClient(port, hostname, sshEnabled, credentials);
}

exports.OAuth.prototype._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
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
  if( extra_params ) {
    for( var key in extra_params ) {
         oauthParameters[key]= extra_params[key];
    }
  }
  if( !post_content_type ) {
    post_content_type= "application/x-www-form-urlencoded";
  }

  var parsedUrl= URL.parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  if( parsedUrl.query ) {
   var extraParameters= querystring.parse(parsedUrl.query);
   for(var key in extraParameters ) {
     oauthParameters[key]= extraParameters[key];
   }
  }

  var sig= this._getSignature( method,  url,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  var orderedParameters= this._sortRequestParams( oauthParameters );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  
  var query=""; 
  for( var i= 0 ; i < orderedParameters.length; i++) {
    query+= this._encodeData(orderedParameters[i][0])+"="+ this._encodeData(orderedParameters[i][1]) + "&";
  }
  query= query.substring(0, query.length-1);


  var oauthProvider;
  if( parsedUrl.protocol == "https:" ) {
    oauthProvider= this._createClient(parsedUrl.port, parsedUrl.hostname, true, crypto.createCredentials({}));
  }
  else {
    oauthProvider= this._createClient(parsedUrl.port, parsedUrl.hostname);
  }

  var headers= {};
  headers["Authorization"]= this._buildAuthorizationHeaders(orderedParameters);
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

  if( method == "POST"  && ( post_body == null && extra_params != null) ) {
    post_body= querystring.stringify(extra_params);
  }

  headers["Content-length"]= post_body ? post_body.length : 0; //Probably going to fail if not posting ascii
  headers["Content-Type"]= post_content_type;
   
  var path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
  if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
  else path= parsedUrl.pathname;

  var request = oauthProvider.request(method,  path , headers);
  if( callback ) {
    var data=""; 
    var self= this;
    request.addListener('response', function (response) {
      response.setEncoding('utf8');
      response.addListener('data', function (chunk) {
        data+=chunk;
      });
      response.addListener('end', function () {
        if( response.statusCode != 200 ) {
          callback({ statusCode: response.statusCode, data: data });
        } else {
          callback(null, data, response);
        }
      });
    });
  
    request.socket.addListener("error",callback);
    if( method == "POST" && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    request.end();
  }
  else {
    if( method == "POST" && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    return request;
  }
  
  return;
}

exports.OAuth.prototype.getOAuthAccessToken= function(oauth_token, oauth_token_secret, oauth_verifier,  callback) {
  var extraParams= {};
  if( typeof oauth_verifier == "function" ) {
    callback= oauth_verifier;
  } else {
    extraParams.oauth_verifier= oauth_verifier;
  }
  
   this._performSecureRequest( oauth_token, oauth_token_secret, "GET", this._accessUrl, extraParams, null, null, function(error, data, response) {
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

// Deprecated
exports.OAuth.prototype.getProtectedResource= function(url, method, oauth_token, oauth_token_secret, callback) {
  this._performSecureRequest( oauth_token, oauth_token_secret, method, url, null, "", null, callback );
}

exports.OAuth.prototype.get= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "GET", url, null, "", null, callback );
}

exports.OAuth.prototype.post= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  var extra_params= null;
  if( typeof post_content_type == "function" ) {
    callback= post_content_type;
    post_content_type= null;
  }
  if( typeof post_body != "string" ) {
    post_content_type= "application/x-www-form-urlencoded"
    extra_params= post_body;
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, "POST", url, extra_params, post_body, post_content_type, callback );
}
 
exports.OAuth.prototype.getOAuthRequestToken= function(extraParams, callback) {
  if( typeof extraParams == "function" ){
    callback = extraParams;
    extraParams = {};
  }

  // Callbacks are 1.0A related 
  if( this._authorize_callback ) {
    extraParams["oauth_callback"]= this._authorize_callback;
  }
  this._performSecureRequest( null, null, "POST", this._requestUrl, extraParams, null, null, function(error, data, response) {
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

exports.OAuth.prototype.signUrl= function(url, oauth_token, oauth_token_secret, method) {
  var collectedParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(this._nonceSize),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };

  if( oauth_token ) {
    collectedParameters["oauth_token"]= oauth_token;
  }
  if( method === undefined ) {
    var method= "GET";
  }

  var parsedUrl= URL.parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  if( parsedUrl.query ) {
   var queryParams= querystring.parse(parsedUrl.query);
   for(var key in queryParams ) {
     collectedParameters[key]= queryParams[key];
   }
  }

  var sig= this._getSignature( method,  url,  this._normaliseRequestParams(collectedParameters), oauth_token_secret);
  var orderedParameters= this._sortRequestParams( collectedParameters );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];

  var query=""; 
  for( var i= 0 ; i < orderedParameters.length; i++) {
    query+= orderedParameters[i][0]+"="+ this._encodeData(orderedParameters[i][1]) + "&";
  }
  query= query.substring(0, query.length-1);
 
  return parsedUrl.protocol + "//"+ parsedUrl.host + parsedUrl.pathname + "?" + query;
};




