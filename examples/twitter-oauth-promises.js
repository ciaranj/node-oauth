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

var OAuth = require("../index").PromiseOAuth;

// Setting up the OAuth client
var requestUrl = "https://api.twitter.com/oauth/request_token";
var accessUrl = "https://api.twitter.com/oauth/access_token";
var version = "1.0";
var authorizeCallback = "oob";
var signatureMethod = "HMAC-SHA1";
var nonceSize = null;
var customHeaders = null;

// Go to https://dev.twitter.com/oauth/overview/application-owner-access-tokens
// to fill these in:
var consumerKey = "your consumer key";
var consumerSecret = "your consumer secret";

var client = new OAuth(
  requestUrl, accessUrl,
  consumerKey, consumerSecret,
  version,
  authorizeCallback,
  signatureMethod,
  nonceSize,
  customHeaders
);

// Making a request to the API
var url = "https://api.twitter.com/1.1/statuses/home_timeline.json";

// Go to https://dev.twitter.com/oauth/overview/application-owner-access-tokens
// to fill these in:
var accessToken = "your access token";
var accessTokenSecret = "your access token secret";

client.get(url, accessToken, accessTokenSecret).then(function(data, response) {
  console.log("Data: " + data);
  console.log("Response: " + response);
}).catch(function(error) {
  console.log("Error: " + error);
});
