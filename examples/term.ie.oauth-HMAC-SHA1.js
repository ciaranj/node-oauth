/**
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

var util= require('util')

var OAuth= require('../lib/oauth').OAuth;

var oa= new OAuth("http://term.ie/oauth/example/request_token.php",
                  "http://term.ie/oauth/example/access_token.php",
                  "key",
                  "secret",
                  "1.0",
                  null,
                  "HMAC-SHA1")

oa.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, results){
  if(error) util.puts('error :' + error)
  else { 
    util.puts('oauth_token :' + oauth_token)
    util.puts('oauth_token_secret :' + oauth_token_secret)
    util.puts('requestoken results :' + util.inspect(results))
    util.puts("Requesting access token")
    oa.getOAuthAccessToken(oauth_token, oauth_token_secret, function(error, oauth_access_token, oauth_access_token_secret, results2) {
      util.puts('oauth_access_token :' + oauth_access_token)
      util.puts('oauth_token_secret :' + oauth_access_token_secret)
      util.puts('accesstoken results :' + util.inspect(results2))
      util.puts("Requesting access token")
      var data= "";
      oa.getProtectedResource("http://term.ie/oauth/example/echo_api.php?foo=bar&too=roo", "GET", oauth_access_token, oauth_access_token_secret,  function (error, data, response) {
          util.puts(data);
      });
    });
  }
})
