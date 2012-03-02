node-oauth
===========
A simple oauth API for node.js .  This API allows users to authenticate against OAUTH providers, and thus act as OAuth consumers. It also has support for OAuth Echo, which is used for communicating with 3rd party media providers such as TwitPic and yFrog.

Tested against Twitter (http://twitter.com), term.ie (http://term.ie/oauth/example/), TwitPic, and Yahoo!

Also provides rudimentary OAuth2 support, tested against facebook connect and github.   For more complete usage examples please take a look at connect-auth (http://github.com/ciaranj/connect-auth)


Change History
============== 

* 0.9.6 - Support for 302 redirects on OAuth2 (Thanks Patrick Negri). Some code tidying. ( Thanks to Raoul Millais )
* 0.9.5 - Allow usage of HTTP verbs other than GET for retrieving the access and request tokens (OAuth1) (Thanks to Raoul Millais)
* 0.9.4 - Support for OAuth providers that drop connections (don't send response lengths? [Google]) And change OAuth2 getOAuthAccessToken to POST rather than GET ( Possible Breaking change!!! ... re-tested against Google, Github, Facebook, FourSquare and Janrain and seems ok .. is closer to the spec (v20) )
* 0.9.3 - Adds support for following 301 redirects (Thanks bdickason) 
* 0.9.2 - Correct content length calculated for non-ascii post bodies (Thanks selead) 
Allowed for configuration of the 'access token' name used when requesting protected resources (OAuth2)
* 0.9.1 - Added support for automatically following 302 redirects (Thanks neyric) Added support for OAuth Echo (Thanks Ryan LeFevre). Improved handling of 2xx responses (Thanks Neil Mansilla).
* 0.9.0 - Compatibility fixes to bring node-oauth up to speed with node.js 0.4x [thanks to Rasmus Andersson for starting the work ]
* 0.8.4 - Fixed issue #14 (Parameter ordering ignored encodings).  Added support for repeated parameter names. Implements issue #15 (Use native SHA1 if available, 10x speed improvement!). Fixed issue #16 (Should use POST when requesting access tokens.).  Fixed Issue #17 (OAuth2 spec compliance).  Implemented enhancement #13 (Adds support for PUT & DELETE http verbs). Fixes issue #18 (Complex/Composite url arguments [thanks novemberborn])
* 0.8.3 - Fixed an issue where the auth header code depended on the Array's toString method (Yohei Sasaki) Updated the getOAuthRequestToken method so we can access google's OAuth secured methods. Also re-implemented and fleshed out the test suite.
* 0.8.2 - The request returning methods will now write the POST body if provided (Chris Anderson), the code responsible for manipulating the headers is a bit safe now when working with other code (Paul McKellar) and tweaked the package.json to use index.js instead of main.js
* 0.8.1 - Added mechanism to get hold of a signed Node Request object, ready for attaching response listeners etc. (Perfect for streaming APIs)
* 0.8.0 - Standardised method capitalisation, the old getOauthAccessToken is now getOAuthAccessToken (Breaking change to existing code)
* 0.7.7 - Looks like non oauth_ parameters where appearing within the Authorization headers, which I believe to be incorrect.
* 0.7.6 - Added in oauth_verifier property to getAccessToken required for 1.0A
* 0.7.5 - Added in a main.js to simplify the require'ing of OAuth
* 0.7.4 - Minor change to add an error listener to the OAuth client (thanks troyk)
* 0.7.3 - OAuth 2 now sends a Content-Length Http header to keep nginx happy :)
* 0.7.2 - Fixes some broken unit tests!
* 0.7.0 - Introduces support for HTTPS end points and callback URLS for OAuth 1.0A and Oauth 2 (Please be aware that this was a breaking change to the constructor arguments order)

Contributors
============

* Ciaran Jessup - ciaranj@gmail.com
* Mark Wubben - http://equalmedia.com/
* Ryan LeFevre - http://meltingice.net
* Raoul Millais
* Patrick Negri - http://github.com/pnegri
