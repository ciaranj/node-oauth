var sha1= require('./sha1'),
    http= require('http'),
    URL= require('url'); 

exports.OAuth= function(requestUrl, accessUrl, authorizeUrl, consumerKey, consumerSecret, version, signatureMethod) {
  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._authorizeUrl= authorizeUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  this._version= version;
  this._signatureMethod= signatureMethod;
};

exports.OAuth.prototype._getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
}

exports.OAuth.prototype._encodeData= function(toEncode){
 if( toEncode == null || toEncode == "" ) return ""
 else {
    var result= encodeURIComponent(toEncode);

    // Fix the mismatch between OAuth's  RFC2396's and Javascript's beliefs in what is right and wrong ;)
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
  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
}

exports.OAuth.prototype._splitQueryString= function(stringToSplit) {
  var result= {};
  var parameters= stringToSplit.split("&");
  for(var key in parameters) {
    var parameterPair= parameters[key].split("=");
    result[parameterPair[0]]= parameterPair[1];
  }
  return result;
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
      args+= argument_pairs[i][0];
      args+= "="
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }     
  return args;
}

exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData(parameters);
  return method.toUpperCase() + "&" + url + "&" + parameters;
}

exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret ); 

   var key= this._consumerSecret + "&" + tokenSecret;

   //TODO: whilst we support different signature methods being passed
   // we currenting only do SHA1-HMAC
   var hash= sha1.HMACSHA1(key, signatureBase);
   signature = this._encodeData(hash);

   return signature;
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

exports.OAuth.prototype.getOauthAccessToken= function(oauth_token, oauth_token_secret, callback) {
  require('sys').puts('getOauthAccessToken')
   var oauthParameters= {
       "oauth_timestamp":        this._getTimestamp(),
       "oauth_nonce":            this._getNonce(32),
       "oauth_version":          this._version,
       "oauth_signature_method": this._signatureMethod,
       "oauth_consumer_key":     this._consumerKey,
       "oauth_token": oauth_token
   };

   var method= "GET";
   var sig= this._getSignature( method,  this._accessUrl,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
                          
   var orderedParameters= this._sortRequestParams( oauthParameters );  
   orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
   
   var query=""; 
   for( var i= 0 ; i < orderedParameters.length; i++) {
     query+= orderedParameters[i][0]+"="+ orderedParameters[i][1] + "&";
   }
   query= query.substring(0, query.length-1);
   var oauthProvider=  http.createClient(80, 'twitter.com');
   var headers= {'Host': 'twitter.com'}
   var request = oauthProvider.request("GET", "/oauth/access_token"+"?"+query, headers);
   var data=""; 
   var self= this;
   request.addListener('response', function (response) {
     response.setEncoding('utf8');
     response.addListener('data', function (chunk) {
       data+=chunk;
     });
     response.addListener('end', function () {
       if( response.statusCode != 200 ) {
         callback( response.statusCode +" : " + data );
       } else {
         var results= self._splitQueryString(data);  
         var oauth_token= results["oauth_token"];
         results["oauth_token"]= undefined;
         var oauth_token_secret= results["oauth_token_secret"];
         results["oauth_token_secret"]= undefined;
         callback(null, oauth_token, oauth_token_secret, results );
       }
     });
   });
   request.end();
 }

exports.OAuth.prototype.getOAuthRequestToken= function(callback) {
  require('sys').puts('getOauthRequestToken')
  
  var oauthParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(32),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };
  var method= "POST"; 
  require('sys').puts(this._requestUrl)
  var sig= this._getSignature( method,  this._requestUrl,  this._normaliseRequestParams(oauthParameters));


  var orderedParameters= this._sortRequestParams( oauthParameters );  
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  var headers= {};

  // build request authorization header
  var authHeader="OAuth "; 
  for( var i= 0 ; i < orderedParameters.length; i++) {
    authHeader+= orderedParameters[i][0]+"=\""+orderedParameters[i][1] +"\",";
  }
  authHeader= authHeader.substring(0, authHeader.length-1);

  headers["Authorization"]= authHeader;
  headers["Host"] = "twitter.com"
  headers["Accept"]= "*/*"
  headers["Connection"]= "close"
  headers["User-Agent"]= "Express authentication"
  headers["Content-length"]= 0
  headers["Content-Type"]= "application/x-www-form-urlencoded"
  
  var oauthProvider=  http.createClient(80, 'twitter.com');
  var request = oauthProvider.request(method, "/oauth/request_token", headers);
  var data=""; 
  var self= this;
  request.addListener('response', function (response) {
    response.setEncoding('utf8');
    response.addListener('data', function (chunk) {
      data+=chunk;
    });
    response.addListener('end', function () {
      if( response.statusCode != 200 ) {
        callback( response.statusCode +" : " + data );
      } else {
        var results= self._splitQueryString(data);  

        var oauth_token= results["oauth_token"];
        var oauth_token_secret= results["oauth_token_secret"];
        delete results["oauth_token"];
        delete results["oauth_token_secret"];
        callback(null, oauth_token, oauth_token_secret, (self._authorizeUrl + oauth_token),  results );
      }
    });
  });
  request.end();
}





