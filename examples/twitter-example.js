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

var http = require("http");
var OAuth = require("../lib/oauth.js").OAuth;
var nodeUrl = require("url");
var clientID = "";
var clientSecret = "";
var callbackURL = "http://localhost:8080/callback";

var oa = new OAuth(
  "https://api.twitter.com/oauth/request_token",
  "https://api.twitter.com/oauth/access_token",
  clientID,
  clientSecret,
  "1.0",
  callbackURL,
  "HMAC-SHA1"
);

http.createServer(function (request, response) {
  oa.getOAuthRequestToken(function (error, oAuthToken, oAuthTokenSecret, results) {
    var urlObj = nodeUrl.parse(request.url, true);
    var handlers = {
      "/": function (request, response) {
        /**
         * Creating an anchor with authURL as href and sending as response
         */
        oa.getOAuthRequestToken(function (error) {
          var statusCode;
          var body;
          var authURL;
          if (error) {
            statusCode = 401;
            body = "Error: " + error.data;
          } else {
            statusCode = 200;
            authURL = "https://api.twitter.com/oauth/authorize?oauth_token=" + oAuthToken;
            body = "<a href='" + authURL + "'> Get Code </a>";
          }
          response.writeHead(statusCode, {
            "Content-Length": body.length,
            "Content-Type": "text/html"
          });
          response.end(body);
        });
      },
      "/callback": function (request, response) {
        /** Obtaining access_token */
        var getOAuthRequestTokenCallback = function (error, oAuthAccessToken, oAuthAccessTokenSecret, results) {
          if (error) {
            console.log(error);
            response.end(JSON.stringify({
              message: "Error occured while getting access token",
              error: error
            }));
            return;
          }

          oa.get(
            "https://api.twitter.com/1.1/account/verify_credentials.json",
            oAuthAccessToken,
            oAuthAccessTokenSecret,
            function (error, twitterResponseData, result) {
              if (error) {
                console.log(error);
                response.end(JSON.stringify(error));
                return;
              }
              try {
                console.log(JSON.parse(twitterResponseData));
              } catch (parseError) {
                console.log(parseError);
              }
              console.log(twitterResponseData);
              response.end(twitterResponseData);
            });
        };

        oa.getOAuthAccessToken(
          urlObj.query.oauth_token,
          oAuthTokenSecret,
          urlObj.query.oauth_verifier,
          getOAuthRequestTokenCallback
        );
      }
    };
    handlers[urlObj.pathname](request, response);
  });
}).listen(8080);
