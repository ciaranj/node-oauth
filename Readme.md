# Oauth-tunnel [![NPM version](https://badge.fury.io/js/oauth-tunnel.png)](http://badge.fury.io/js/oauth-tunnel) [![Build Status](https://travis-ci.org/darul75/oauth-tunnel.png?branch=master)](https://travis-ci.org/darul75/oauth-tunnel) [![Total views](https://sourcegraph.com/api/repos/github.com/darul75/oauth-tunnel/counters/views.png)](https://sourcegraph.com/github.com/darul75/node-oauth-tunnel)


Fork for oauth with tunnel (for proxy) integration

* `oauth`  https://github.com/ciaranj/node-oauth
* `tunnel` https://github.com/koichik/node-tunnel


## Why ?

Because proxy may cause you issue as usual.

## Install

~~~
npm install oauth-tunnel
~~~

## Usage

### OAUTH2

```javascript
var OAuth2 = require('OAuth2');

var twitterConsumerKey = '';
var twitterConsumerSecret = '';
var oauth2 = new OAuth2.OAuth2(twitterConsumerKey, twitterConsumerSecret, 
    'https://api.twitter.com/', 
    null,
    'oauth2/token', 
    null,
    // YOUR PROXY ADDR, SEE TUNNEL OPTIONS BELOW
    {
        proxy: {
            host: '127.0.0.1', 
            port: 8081
        }
    }
);
oauth2.getOAuthAccessToken(
    '',
    {'grant_type':'client_credentials'},
    function (e, access_token, refresh_token, results){      
        console.log('bearer: ',access_token);
    });
```

### OAUTH1

```javascript
var OAuth = require('OAuth');

var twitterConsumerKey = '';
var twitterConsumerSecret = '';
var twitterAccessToken = '';
var twitterTokenSecret = '';

var oauth = new OAuth.OAuth(
  'https://api.twitter.com/oauth/request_token',
  'https://api.twitter.com/oauth/access_token',
  twitterConsumerKey,
  twitterConsumerSecret,
  '1.0A',
  null,
  'HMAC-SHA1',
  null,
  null,
  // YOUR PROXY ADDR, SEE TUNNEL OPTIONS BELOW
  {
    proxy: {
        host: '127.0.0.1', 
        port: 8081
    }
  }
);
oauth.get(
  'https://api.twitter.com/1.1/trends/place.json?id=23424977',
  twitterAccessToken, //test user token
  twitterTokenSecret, //test user secret            
  function (e, data, res){
    if (e) console.error(e);        
    console.log(require('util').inspect(data));
    done();      
  });    
});
```

## Options

* Tunnel proxy options parameters : https://github.com/koichik/node-tunnel
* Oauth options parameters : https://github.com/ciaranj/node-oauth

## License

The MIT License (MIT)

Copyright (c) 2013 Julien Valéry

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
