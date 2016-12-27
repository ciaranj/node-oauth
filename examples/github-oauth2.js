/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2016 Rudolf Olah
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

var OAuth2 = require("../index").PromiseOAuth2;

var clientId = "";
var clientSecret = "";

// Fill these in:
var user = "USER";
var personalAccessToken = "PERSONAL_ACCESS_TOKEN";

var baseSiteUrl = "https://" + user + ":" + personalAccessToken + "@api.github.com/";
var authorizePath = "oauth2/authorize";
var accessTokenPath = "oauth2/access_token";
var customHeaders = null;

function jsonParse(data) {
  return JSON.parse(data);
}

var oauth2 = new OAuth2(
  clientId, clientSecret, baseSiteUrl, authorizePath, accessTokenPath, customHeaders
);

var url = "https://api.github.com/users/" + user + "/received_events";
oauth2
  .get(url, personalAccessToken)
  .then(jsonParse)
  .then(function(json) {
    for (var i = 0; i < json.length; i += 1) {
      console.log(json[i]["id"] + ": " + json[i].type);
    }
  })
  .catch(function(err) {
    console.log("Error: " + err);
  });
