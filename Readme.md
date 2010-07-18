node-oauth
===========
A simple oauth API for node.js .  This API allows users to authenticate against OAUTH providers, and thus act as OAuth consumers

Tested against both Twitter (http://twitter.com),  term.ie (http://term.ie/oauth/example/) and Yahoo! 

Also provides rudimentary OAuth2 support, tested against facebook connect and github.   For more complete usage examples please take a look
at express-auth (http://github.com/ciaranj/express-auth) 

Change History
==============
* 0.7.6 - Added in oauth_verifier property to getAccessToken required for 1.0A
* 0.7.5 - Added in a main.js to simplify the require'ing of OAuth
* 0.7.4 - Minor change to add an error listener to the OAuth client (thanks troyk)
* 0.7.3 - OAuth 2 now sends a Content-Length Http header to keep nginx happy :)
* 0.7.2 - Fixes some broken unit tests! 
* 0.7.0 - Introduces support for HTTPS end points and callback URLS for OAuth 1.0A and Oauth 2 (Please be aware that this was a breaking change to the constructor arguments order)
