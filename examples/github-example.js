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
var qs = require("querystring");
// var OAuth = require("oauth"), OAuth2 = OAuth.OAuth2;
var OAuth2 = require("../lib/oauth2.js").OAuth2;

var clientID = "";
var clientSecret = "";
var oauth2 = new OAuth2(
  clientID,
  clientSecret,
  "https://github.com/", 
  "login/oauth/authorize",
  "login/oauth/access_token",
  null /** Custom headers */
);

http.createServer(function (req, res) {
  var p = req.url.split("/");
  var pLen = p.length;
  
  /**
   * Authorised url as per github docs:
   * https://developer.github.com/v3/oauth/#redirect-users-to-request-github-access
   * 
   * getAuthorizedUrl: https://github.com/ciaranj/node-oauth/blob/master/lib/oauth2.js#L148
   * Adding params to authorize url with fields as mentioned in github docs
   *
   */
  var authURL = oauth2.getAuthorizeUrl({
    redirect_uri: "http://localhost:8080/code",
    scope: ["repo", "user"],
    state: "some random string to protect against cross-site request forgery attacks"
  });

  /**
   * Creating an anchor with authURL as href and sending as response
   */
  var body = "<a href='" + authURL + "'> Get Code </a>";
  if (pLen === 2 && p[1] === "") {
    res.writeHead(200, {
      "Content-Length": body.length,
      "Content-Type": "text/html" });
    res.end(body);
  } else if (pLen === 2 && p[1].indexOf("code") === 0) {
    /** Github sends auth code so that access_token can be obtained */
    var qsObj = {};
    
    /** To obtain and parse code="..." from code?code="..." */
    qsObj = qs.parse(p[1].split("?")[1]); 

    /** Obtaining access_token */
    oauth2.getOAuthAccessToken(
      qsObj.code,
      {"redirect_uri": "http://localhost:8080/code/"},
      function (error, access_token, refresh_token, results) {
        if (error) {
          console.log(error);
          res.end(error);
        } else if (results.error) {
          console.log(results);
          res.end(JSON.stringify(results));
        } else {
          console.log("Obtained access_token: ", access_token);
          res.end( access_token);
        }
      });

  } else {
    // Unhandled url
  }

}).listen(8080);
