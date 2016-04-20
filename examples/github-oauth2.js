var OAuth2 = require('../index').PromiseOAuth2;

var clientId = '';
var clientSecret = '';

// Fill these in:
var user = 'USER';
var personalAccessToken = 'PERSONAL_ACCESS_TOKEN';

var baseSiteUrl = 'https://' + user + ':' + personalAccessToken + '@api.github.com/';
var authorizePath = 'oauth2/authorize';
var accessTokenPath = 'oauth2/access_token';
var customHeaders = null;

var oauth2 = new OAuth2(
  clientId, clientSecret, baseSiteUrl, authorizePath, accessTokenPath, customHeaders
);

var url = 'https://api.github.com/users/' + user + '/received_events';
oauth2
  .get(url, personalAccessToken)
  .then(jsonParse)
  .then(function(json) {
    for (var i = 0; i < json.length; i += 1) {
      console.log(json[i]['id'] + ': ' + json[i].type);
    }
  })
  .catch(function(err) {
    console.log('Error: ' + err);
  });

function jsonParse(data) {
  return JSON.parse(data);
}
