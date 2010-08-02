var querystring= require('querystring'),
    crypto= require('crypto'),
    http= require('http'),
    URL= require('url');

var sys= require('sys');

exports.OAuth2= function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath) {
  this._clientId= clientId;
  this._clientSecret= clientSecret; 
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize"
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token"
}



exports.OAuth2.prototype._getAccessTokenUrl= function( params ) {
  var params= params || {};
  params['client_id'] = this._clientId;  
  params['client_secret'] = this._clientSecret;  
  params['type']= 'web_server';
  
  return this._baseSite + this._accessTokenUrl + "?" + querystring.stringify(params);
}

exports.OAuth2.prototype._request= function(method, url, headers, access_token, callback) {

  var creds = crypto.createCredentials({ });  
  var parsedUrl= URL.parse( url, true );   
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;
  var httpClient = http.createClient(parsedUrl.port, parsedUrl.hostname, true, creds);
  
  var realHeaders= {};
  if( headers ) {
    for(var key in headers) {
      realHeaders[key] = headers[key];
    }
  }
  realHeaders['Host']= parsedUrl.host;

  //TODO: Content length should be dynamic when dealing with POST methods....
  realHeaders['Content-Length']= 0;
  if( access_token ) {
    if( ! parsedUrl.query ) parsedUrl.query= {};
    parsedUrl.query["access_token"]= access_token;
  }

  var request = httpClient.request(method, parsedUrl.pathname + "?" + querystring.stringify(parsedUrl.query), realHeaders );   

  httpClient.addListener("secure", function () {
/* // disable verification for now.      

var verified = httpClient.verifyPeer();
      if(!verified) this.end();   */
  });  

  var result= "";
  request.addListener('response', function (response) { 
    response.addListener("data", function (chunk) {
      result+= chunk
    });
    response.addListener("end", function () {
      if( response.statusCode != 200 ) {
        callback({ statusCode: response.statusCode, data: result });
      } else {
        callback(null, result, response);
      }
    });
  });

  request.end();
} 


exports.OAuth2.prototype.getAuthorizeUrl= function( params ) {
  var params= params || {};
  params['client_id'] = this._clientId;
  params['type'] = 'web_server';
  return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params);
}

exports.OAuth2.prototype.getOAuthAccessToken= function(code, params, callback) {
  var params= params || {};
  params['code']= code;

  this._request("POST", this._getAccessTokenUrl(params), {}, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results= querystring.parse(data);
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token);
    }
  });
} 

// Deprecated
exports.OAuth2.prototype.getProtectedResource= function(url, access_token, callback) {
  this._request("GET", url, {}, access_token, callback );
}

exports.OAuth2.prototype.get= function(url, access_token, callback) {
  this._request("GET", url, {}, access_token, callback );
}
