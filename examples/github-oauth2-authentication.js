/**
 * Example of using Hooks (request:before and request:after) with
 * OAuth2.
 */
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const randomstring = require("randomstring");

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: "keyboard cat",
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
}));

const clientId = "YOURCLIENTID";
const clientSecret = "YOURCLIENTSECRET";
const scope = "user";
const redirectUrl = "http://localhost:" + port + "/github/callback";
const baseUrl = "https://github.com";
const authorizeUrl = "/login/oauth/authorize";
const tokenUrl = "/login/oauth/access_token";

const OAuth2 = require("../lib/oauth2").OAuth2;
const oa2 = new OAuth2(clientId, clientSecret, baseUrl, authorizeUrl, tokenUrl, {});

oa2.on("request:before", function (options, postBody, done) {
  // here you can add anything you want to the request before
  // execution can add new headers or add new data to body.
  //
  // NOTE: you must call done and send 3 parameters without exception
  // 3rd parameter must to be true if you want to execute request in
  // this moment.
  done(options, postBody, true);
});

oa2.on("request:after", function (status, response) {
  console.log("Status:" + JSON.stringify(status));
  console.log("Response: " + JSON.stringify(response));
});

app.set("oa", oa2);

app.get("/", function (req, res) {
  res.send("<a href='/github/auth'>Sign In with Github</a>");
});

app.get("/github/auth", function (req, res) {
  const oa = req.app.get("oa");
  const state = randomstring.generate(7);
  req.session.state = state;
  const params = {
    "client_id": oa._clientId,
    "redirect_uri": redirectUrl,
    "scope": scope,
    "state": state,
    "allow_signup": "false"
  };
  const url = oa.getAuthorizeUrl(params);
  res.redirect(url);
});

app.get("/github/callback", function (req, res) {
  const oa = req.app.get("oa");
  const code = req.query.code;
  const requestState = req.query.state;
  if (requestState !== req.session.state) {
    return res.send("Github error state mismatch");
  }
  oa.getOAuthAccessToken(code, {}, function (accessToken, refreshToken, result) {
    res.send("Github must authenticated this accessToken: " + accessToken + " - refreshToken: " + refreshToken);
  });
});

app.listen(port, function () {
  console.log("github outh2 example running on " + port);
});
