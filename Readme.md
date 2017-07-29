# node-oauth

[![Build Status](https://travis-ci.org/omouse/node-oauth-libre.svg)](https://travis-ci.org/omouse/node-oauth-libre)
[![License](http://img.shields.io/:license-gpl3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0.html)
[![Flattr This](http://button.flattr.com/flattr-badge-large.png)](https://flattr.com/submit/auto?fid=y0jx3j&url=https%3A%2F%2Fgithub.com%2Fomouse%2Fnode-oauth-libre)

A simple oauth API for node.js .  This API allows users to authenticate against OAUTH providers, and thus act as OAuth consumers. It also has support for OAuth Echo, which is used for communicating with 3rd party media providers such as TwitPic and yFrog.

Tested against Twitter (http://twitter.com), term.ie (http://term.ie/oauth/example/), TwitPic, and Yahoo!

Also provides rudimentary OAuth2 support, tested against facebook, github, foursquare, google and Janrain.   For more complete usage examples please take a look at connect-auth (http://github.com/ciaranj/connect-auth)

## Related Libraries

- [passport-oauth2-libre](https://github.com/caco0516/passport-oauth2-libre) Passport OAuth2 Strategy using node-oauth-libre.

## License and Copyright

**This code is covered under the GNU GPL version 3 or later with parts of the code also covered by the MIT license.**

If you modify the code in this project, your changes will be under the GNU GPL version 3 or later.

If you go to the original project and modify the code there, your changes will be under the MIT license.

*Note: if you submit patches to the original project and they are applied here, I will assume that they
are under the MIT license.* But someone else will have to go through the work to extract them away from
the GPLv3 bits if they want to use them in a proprietary project

# Installation

    npm install oauth-libre

# Build the Docs

Requires JSDoc to be installed:

    npm run build-docs

# Examples

## Using Promises

Using promises is *optional*.

Install the bluebird promises library:

    npm install bluebird

An example of using oauth-libre with OAuth2 and Promises to access the Github API:

```
var OAuth2 = require('oauth-libre').PromiseOAuth2;

var clientId = '';
var clientSecret = '';

// Fill these in:
var user = 'USER';
var personalAccessToken = 'PERSONAL_ACCESS_TOKEN';

var baseSiteUrl = 'https://' + user + ':' + personalAccessToken + '@api.github.com/';
var authorizePath = 'oauth2/authorize';
var accessTokenPath = 'oauth2/access_token';
var customHeaders = null;

var oauth2 = new OAuth2(
  clientId, clientSecret, baseSiteUrl, authorizePath, accessTokenPath, customHeaders
);

var url = 'https://api.github.com/users/' + user + '/received_events';
oauth2
  .get(url, personalAccessToken)
  .then(jsonParse)
  .then(function(json) {
    for (var i = 0; i < json.length; i += 1) {
      console.log(json[i]['id'] + ': ' + json[i].type);
    }
  })
  .catch(function(err) {
    console.log('Error: ' + err);
  });

function jsonParse(data) {
  return JSON.parse(data);
}
```

Note that in the first line you must explicitly import OAuth2 with promises.

## OAuth1.0

Example of using OAuth 1.0 with the Twitter API.

```javascript
describe('OAuth1.0',function(){
  var OAuth = require('oauth-libre');

  it('tests trends Twitter API v1.1',function(done){
    var oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      'your application consumer key',
      'your application secret',
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    oauth.setDefaultContentType('application/json');
    oauth.get(
      'https://api.twitter.com/1.1/trends/place.json?id=23424977',
      'your user token for this app', //test user token
      'your user secret for this app', //test user secret
      function (e, data, res){
        if (e) console.error(e);
        console.log(require('util').inspect(data));
        done();
      });
  });
});
```

## OAuth2.0

### Usage

```javascript
var OAuth2 = require('oauth-libre').OAuth2;

console.log("Login here to get an authorization code: " + oauth2.getAuthorizeUrl());

var oauth2 = new OAuth2(
  "client_id", // client id
  "client_secret", // client secret
  "http://localhost:3000/", // base site url
  null, // authorize path
  "/oauth/token", // access token path
  null // custom headers object
);

oauth2.getOAuthAccessToken(
  "auth_code",
  {
    "grant_type": "authorization_code",
    "redirect_uri": "http://example.com/redirect_uri"
  },
  function(error, accessToken, refreshToken, results) {
    if (error) {
      console.log("Error: " + error);
    } else {
      console.log("Results: " + results);
    }
  }
);
```

### Hooks
OAuth 2.0 implements hooks for every request before and after it is executed. We're using the [EventEmitter](https://nodejs.org/api/events.html) Node.js class to implement this.

#### request:before
This event is emitted before the HTTP (or HTTPS) request is executed. At this point we can modify the information in the request, such as the headers and POST data. Also we are given a `done` function because this event blocks request execution and we need to specify when to resume the current process.

Let's see an example:

```javascript
  oa2.on('request:before', (options, postBody, done) => {
    // here you can add anything you want to the request before execution
    // can add new headers or add new data to body.
    //
    // NOTE: you must call done and send 3 parameters without exception.
    // The 3rd parameter must to be true if you want to execute request
    // immediately.
    done(options, postBody, true);
  });
```

You must call `done(modifiedOptions, modifiedPostBody, shouldExecute)` always. The `shouldExecute` parameter exists because if we have more listeners for the `request:before` event we want to make sure all of the listeners are able to receive the event. The request should execute only once, that's why we have this parameter to tell event that we want to execute the request immediately.

### request:after
This event is emitted after the request has been executed, we receive information about status and body of the response.

```javascript
  oa2.on('request:after', (status, response) => {
    console.log('Status :' + JSON.stringify(status));
    console.log('Response : ' + JSON.stringify(response));
  });
```

### Test

```javascript
describe('OAuth2',function() {
  var OAuth = require('oauth-libre');

   it('gets bearer token', function(done){
     var OAuth2 = OAuth.OAuth2;
     var twitterConsumerKey = 'your key';
     var twitterConsumerSecret = 'your secret';
     var oauth2 = new OAuth2(server.config.keys.twitter.consumerKey,
       twitterConsumerSecret,
       'https://api.twitter.com/',
       null,
       'oauth2/token',
       null);
     oauth2.getOAuthAccessToken(
       '',
       {'grant_type':'client_credentials'},
       function (e, access_token, refresh_token, results){
       console.log('bearer: ',access_token);
       done();
     });
   });
```

## Examples Using Web-Based Interface

Included with the source code are examples of using a web-based interface to login with:

* Github: `examples/github-example.js`
* Github OAuth 2.0 and Hooks: `examples/github-oauth2-authentication.js`
* Twitter: `examples/twitter-example.js`

The Google example was removed due to the need for a custom Google-specific OAuth2 library for authentication.

### Example: Authentication with Github

1. Create a Github account
1. Create a new Developer Application (Settings > OAuth applications > Developer Applications)
1. Fill in the Authorization callback URL with `http://localhost:8080/code`
1. Copy the Client ID into `examples/github-example.js` where it says `clientID`
1. Copy the Client Secret into `examples/github-example.js` where it says `clientSecret`
1. Run the web server: `node examples/github-example.js`
1. Open the website: `http://localhost:8080/`
1. Click the link that says "Get Code"
1. Login to Github and authorize the application
1. You will be returned to `http://localhost:8080/code` and should see the access token, on the command-line you will see something like "Obtained access_token: ..."


### Example: Authentication with Github OAuth 2.0 and Hooks

1. Create a Github account
1. Create a new Developer Application (Settings > OAuth applications > Developer Applications)
1. Fill in the Authorization callback URL with `http://localhost:3000/github/callback`
1. Complete this with your information:
```javascript
  const clientId = 'YOURCLIENTID';
  const clientSecret = 'YOURCLIENTSECRET';
  const scope = 'user';
  const redirectUrl = 'http://localhost:' + port + '/github/callback';
  const baseUrl = 'https://github.com';
  const authorizeUrl = '/login/oauth/authorize';
  const tokenUrl = '/login/oauth/access_token';
```
1. Run the web server: `node examples/github-oauth2-authentication.js`
1. Open the website: `http://localhost:3000/`
1. Click the link that says "Sign In with Github"
1. Login to Github and authorize the application
1. You will be returned to `http://localhost:8080/github/callback` and that's it.

### Example: Authentication with Google

*Note: This example has been removed because Google needs a custom OAuth2 client library: https://github.com/google/google-auth-library-nodejs*

### Example: Authentication with Twitter

1. Create a Twitter account
1. Create a new Developer Application https://apps.twitter.com/ > Create New App
1. Fill in the Callback URL with `http://127.0.0.1:8080/callback`
1. Copy the Consumer Key (API Key) into `examples/twitter-example.js` where it says `clientID`
1. Copy the Consumer Secret (API Secret) into `examples/twitter-example.js` where it says `clientSecret`
1. Run the web server: `node examples/twitter-example.js`
1. Open the website: `http://localhost:8080/`
1. Login to Twitter and authorize the application
1. You will be returned to `http://localhost:8080/code` and should see some results from the response on the command-line

# Change History
* 0.9.16
    - OAuth2 hooks for before and after a request is executed
* 0.9.15
    - Promises for OAuth1 and OAuth2 with multiArgs
    - PATCH support for OAuth1 and OAuth2
    - GPLv3+ licensing
    - Code examples updated, tested and working
    - OAuth2: Authorization header added for POST token
    - OAuth1: Able to set HTTPS/HTTP options
    - OAuth1: getOAuthAccessToken now accepts an additional extraParams argument
* 0.9.14
    - OAuth2:   Extend 'successful' token responses to include anything in the 2xx range.
* 0.9.13
    - OAuth2:   Fixes the "createCredentials() is deprecated, use tls.createSecureContext instead" message. (thank you AJ ONeal)
* 0.9.12
    - OAuth1/2: Can now pass Buffer instance directly for PUTs+POSTs (thank you Evan Prodromou)
    - OAuth1:   Improve interoperability with libraries that mess with the prototype. (thank you Jose Ignacio Andres)
    - OAuth2:   Adds PUT support for OAuth2 (thank you Derek Brooks)
    - OAuth1:   Improves use_strict compatibility (thank you Ted Goddard)
* 0.9.11
    - OAuth2:   No longer sends the type=webserver argument with the OAuth2 requests (thank you bendiy)
    - OAuth2:   Provides a default (and overrideable) User-Agent header (thanks to Andrew Martens & Daniel Mahlow)
    - OAuth1:   New followRedirects client option (true by default) (thanks to Pieter Joost van de Sande)
    - OAuth1:   Adds RSA-SHA1 support (thanks to Jeffrey D. Van Alstine  & Michael Garvin &  Andreas Knecht)
* 0.9.10
    - OAuth2:   Addresses 2 issues that came in with 0.9.9, #129 & #125 (thank you José F. Romaniello)
* 0.9.9
    - OAuth1:   Fix the mismatch between the output of querystring.stringify() and this._encodeData(). (thank you rolandboon)
    - OAuth2:   Adds Authorization Header and supports extra headers by default ( thanks to Brian Park)
* 0.9.8
    - OAuth1:   Support overly-strict OAuth server's that require whitespace separating the Authorization Header parameters  (e.g. 500px.com) (Thanks to Christian Schwarz)
    - OAuth1:   Fix incorrect double-encoding of PLAINTEXT OAuth connections (Thanks to Joe Rozner)
    - OAuth1:   Minor safety check added when checking hostnames. (Thanks to Garrick Cheung)
* 0.9.7
    - OAuth2:   Pass back any extra response data for calls to getOAuthAccessToken (Thanks to Tang Bo Hao)
    - OAuth2:   Don't force a https request if given a http url (Thanks to Damien Mathieu)
    - OAuth2:   Supports specifying a grant-type of 'refresh-token' (Thanks to Luke Baker)
* 0.9.6
    - OAuth2:   Support for 302 redirects (Thanks Patrick Negri).
    - OAuth1/2: Some code tidying. ( Thanks to Raoul Millais )
* 0.9.5
    - OAuth1:   Allow usage of HTTP verbs other than GET for retrieving the access and request tokens (Thanks to Raoul Millais)
* 0.9.4
    - OAuth1/2: Support for OAuth providers that drop connections (don't send response lengths? [Google])
    - OAuth2:   Change getOAuthAccessToken to POST rather than GET ( Possible Breaking change!!! ... re-tested against Google, Github, Facebook, FourSquare and Janrain and seems ok .. is closer to the spec (v20) )
* 0.9.3
    - OAuth1:   Adds support for following 301 redirects (Thanks bdickason)
* 0.9.2
    - OAuth1:   Correct content length calculated for non-ascii post bodies (Thanks selead)
    - OAuth1:   Allowed for configuration of the 'access token' name used when requesting protected resources (OAuth2)
* 0.9.1
    - OAuth1:   Added support for automatically following 302 redirects (Thanks neyric)
    - OAuth1:   Added support for OAuth Echo (Thanks Ryan LeFevre).
    - OAuth1:   Improved handling of 2xx responses (Thanks Neil Mansilla).
* 0.9.0
    - OAuth1/2: Compatibility fixes to bring node-oauth up to speed with node.js 0.4x [thanks to Rasmus Andersson for starting the work ]
* 0.8.4
    - OAuth1:   Fixed issue #14 (Parameter ordering ignored encodings).
    - OAuth1:   Added support for repeated parameter names.
    - OAuth1/2: Implements issue #15 (Use native SHA1 if available, 10x speed improvement!).
    - OAuth2:   Fixed issue #16 (Should use POST when requesting access tokens.).
    - OAuth2:   Fixed Issue #17 (OAuth2 spec compliance).
    - OAuth1:   Implemented enhancement #13 (Adds support for PUT & DELETE http verbs).
    - OAuth1:   Fixes issue #18 (Complex/Composite url arguments [thanks novemberborn])
* 0.8.3
    - OAuth1:   Fixed an issue where the auth header code depended on the Array's toString method (Yohei Sasaki) Updated the getOAuthRequestToken method so we can access google's OAuth secured methods. Also re-implemented and fleshed out the test suite.
* 0.8.2
    - OAuth1:   The request returning methods will now write the POST body if provided (Chris Anderson), the code responsible for manipulating the headers is a bit safe now when working with other code (Paul McKellar)
    - Package:  Tweaked the package.json to use index.js instead of main.js
* 0.8.1
    - OAuth1:   Added mechanism to get hold of a signed Node Request object, ready for attaching response listeners etc. (Perfect for streaming APIs)
* 0.8.0
    - OAuth1:   Standardised method capitalisation, the old getOauthAccessToken is now getOAuthAccessToken (Breaking change to existing code)
* 0.7.7
    - OAuth1:   Looks like non oauth_ parameters where appearing within the Authorization headers, which I believe to be incorrect.
* 0.7.6
    - OAuth1:   Added in oauth_verifier property to getAccessToken required for 1.0A
* 0.7.5
    - Package:  Added in a main.js to simplify the require'ing of OAuth
* 0.7.4
    - OAuth1:   Minor change to add an error listener to the OAuth client (thanks troyk)
* 0.7.3
    - OAuth2:   Now sends a Content-Length Http header to keep nginx happy :)
* 0.7.2
    - OAuth1:   Fixes some broken unit tests!
* 0.7.0
    - OAuth1/2: Introduces support for HTTPS end points and callback URLS for OAuth 1.0A and Oauth 2 (Please be aware that this was a breaking change to the constructor arguments order)

# Contributors (In first-name alphabetical order)

* AJ ONeal
* Alex Nuccio - https://github.com/anuccio1
* Andreas Knecht
* Andrew Martins - http://www.andrewmartens.com
* Brian Park - http://github.com/yaru22
* Carlos Castillo Oporta - https://github.com/caco0516
* Christian Schwarz  - http://github.com/chrischw/
* Ciaran Jessup - ciaranj@gmail.com
* Damien Mathieu - http://42.dmathieu.com
* Daniel Mahlow - https://github.com/dmahlow
* Derek Brooks
* Evan Prodromou
* Garrick Cheung - http://www.garrickcheung.com/
* George Haddad - https://github.com/george-haddad
* Jeffrey D. Van Alstine
* Joe Rozer - http://www.deadbytes.net
* Jose Ignacio Andres
* José F. Romaniello - http://github.com/jfromaniello
* Luke Baker - http://github.com/lukebaker
* Mark Wubben - http://equalmedia.com/
* Michael Garvin
* Oleg Zd - https://github.com/olegzd
* Patrick Negri - http://github.com/pnegri
* Pieter Joost van de Sande - https://github.com/pjvds
* Raoul Millais
* Rudolf Olah - https://neverfriday.com
* Ryan LeFevre - http://meltingice.net
* Tang Bo Hao - http://github.com/btspoony
* Ted Goddard
* bendiy - https://github.com/bendiy
* rolandboon - http://rolandboon.com
* cr24osome - https://github.com/cr24osome
