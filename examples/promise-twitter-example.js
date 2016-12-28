/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2016 Oleg Zd
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

/*
 *
 * This is an example of the original Twitter OAuth 1 example, ported
 * over to use the promise library.
 *
 * NOTE: Express should be installed (included here for ease of use,
 *       if you're not using Express, this can be easily done through
 *       Node's http.createSever() call.
 *
 */

var http = require("http");
var OAuth = require("../lib/oauth-promise").OAuth;
var express = require("express");

const callbackURL = "http://localhost:5000/oauth_callback";
const yourConsumerKey = "INSERT YOUR CONSUMER KEY HERE";
const yourConsumerSecret = "INSERT YOUR CONSUMER SECRET KEY HERE";

// Hash that contains the req_token:req_token_secret key vals
var reqTokenSecrets = {};

/*
  STEP 1 - init the OAuth Client!
*/
var oa = new OAuth(
  "https://api.twitter.com/oauth/request_token",
  "https://api.twitter.com/oauth/access_token",
  yourConsumerKey,    // CONSUMER KEY
  yourConsumerSecret, // CONSUMER SECRET
  "1.0",
  callbackURL,
  "HMAC-SHA1"
);

var app = express();
app.get("/", function(req, res) {
  // STEP 2: Ask twitter for a signed request token

  // oAuthToken/Secret used for this this handshake process
  var requestTokenPromise = oa.getOAuthRequestToken();

  /*
    Promise returns data array in the format:

    data[0]: oauth_token
    data[1]: oauth_token_secret
    data[2]: results

  */
  requestTokenPromise.then(function(data){
    // Extract data
    var oauthToken = data[0];
    var oauthTokenSecret = data[1];

    // Get the secret oauth request token
    reqTokenSecrets[oauthToken] = oauthTokenSecret;

    // Redirect user to Twitter Auth
    var redirectURL = "https://api.twitter.com/oauth/authorize" +
        "?oauth_token=" + oauthToken;
    res.redirect(redirectURL);

  });

});


app.get("/oauth_callback", function(req, res) {

  // This is where we get the oauth token, oauth verifier, and give the oauth token secret as well

  /**
   * STEP 4: Get the access token and access token secret - finally what we need! :)
   */
  var accessTokenPromise = oa.getOAuthAccessToken(
    req.query.oauth_token,
    reqTokenSecrets[req.query.oauth_token],
    req.query.oauth_verifier
  );

  /*
    Similar to access token:
    data[0]: access token
    data[1]: access token secret
    data[2]: results
  */
  accessTokenPromise.then(function(data) {
    var accessToken = data[0];
    var accessTokenSecret = data[1];
    var results = data[2];
    // here we get access token, access token secret - this is what we use to access the
    // user"s Twitter resources, you want to store this!
    res.send("Acc token: " + accessToken +
             " \nAcc token secret: " + accessTokenSecret);
  });

});

app.listen(5000, function(){
  console.log("Listening on port 5000");
});

