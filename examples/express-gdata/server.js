/**
 * node-oauth-libre is a Node.js library for OAuth
 *
 * Copyright (C) 2010-2012 Ciaran Jessup
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

var express = require('express');
var logger = require('morgan');
var bodyParser = require('body-parser');
var session = require('express-session');
var querystring = require('querystring');
var OAuth = require('../../index').OAuth;

// Setup the Express.js server
var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: "skjghskdjfhbqigohqdiouk"
}));

// Home Page
app.get('/', function(req, res){
  if(!req.session.oauth_access_token) {
    res.redirect("/google_login");
  }
  else {
    res.redirect("/google_contacts");
  }
});

// Request an OAuth Request Token, and redirects the user to authorize it
app.get('/google_login', function(req, res) {

  var getRequestTokenUrl = "https://accounts.google.com/o/oauth2/v2/auth";

  // GData specifid: scopes that wa want access to
  var gdataScopes = [
    querystring.escape("https://www.googleapis.com/auth/calendar")
  ];

  var url = getRequestTokenUrl + "?scope=" + gdataScopes.join('+');
  var callbackUrl = "http://localhost:8080/google_cb";
  if (req.params['action'] && req.params['action'] != "") {
    callbackUrl +=  "?action=" + querystring.escape(req.param['action']);
  }
  var oa = new OAuth(
    url,
    "https://www.google.com/accounts/OAuthGetAccessToken",
    "anonymous",
    "anonymous",
    "1.0",
    callbackUrl,
    "HMAC-SHA1"
  );

  oa.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, results) {
    if (error) {
      console.log('error');
      console.log(error);
    } else {
      // store the tokens in the session
      req.session.oa = oa;
      req.session.oauth_token = oauth_token;
      req.session.oauth_token_secret = oauth_token_secret;

      // redirect the user to authorize the token
      res.redirect("https://www.google.com/accounts/OAuthAuthorizeToken?oauth_token="+oauth_token);
    }
  });

});

// Callback for the authorization page
app.get('/google_cb', function(req, res) {

  // get the OAuth access token with the 'oauth_verifier' that we received

  var oa = new OAuth(req.session.oa._requestUrl,
                     req.session.oa._accessUrl,
                     req.session.oa._consumerKey,
                     req.session.oa._consumerSecret,
                     req.session.oa._version,
                     req.session.oa._authorize_callback,
                     req.session.oa._signatureMethod);

  console.log(oa);

  oa.getOAuthAccessToken(
    req.session.oauth_token,
    req.session.oauth_token_secret,
    req.param('oauth_verifier'),
    function(error, oauth_access_token, oauth_access_token_secret, results2) {

      if(error) {
        console.log('error');
        console.log(error);
      }
      else {

        // store the access token in the session
        req.session.oauth_access_token = oauth_access_token;
        req.session.oauth_access_token_secret = oauth_access_token_secret;

        res.redirect((req.param('action') && req.param('action') != "") ? req.param('action') : "/google_contacts");
      }

    });

});


function require_google_login(req, res, next) {
  if(!req.session.oauth_access_token) {
    res.redirect("/google_login?action="+querystring.escape(req.originalUrl));
    return;
  }
  next();
};

app.get('/google_calendars', require_google_login, function(req, res) {
  var oa = new OAuth(req.session.oa._requestUrl,
                     req.session.oa._accessUrl,
                     req.session.oa._consumerKey,
                     req.session.oa._consumerSecret,
                     req.session.oa._version,
                     req.session.oa._authorize_callback,
                     req.session.oa._signatureMethod);
  // Example using GData API v2
  // GData Specific Header
  oa._headers['GData-Version'] = '2';

  oa.getProtectedResource(
    "https://www.google.com/calendar/feeds/default/allcalendars/full?alt=jsonc",
    "GET",
    req.session.oauth_access_token,
    req.session.oauth_access_token_secret,
    function (error, data, response) {

      var feed = JSON.parse(data);

      res.render('google_calendars.ejs', {
        locals: { feed: feed }
      });
    });

});

app.listen(8080);
console.log("listening on http://localhost:8080");
