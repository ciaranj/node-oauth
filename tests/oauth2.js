var vows = require('vows'),
    assert = require('assert'),
    OAuth2= require('../lib/oauth2').OAuth2;

vows.describe('OAuth2').addBatch({
    'When handling the access token response': {
        topic: new OAuth2(),
        'we should correctly extract the token if received as form-data': function (oa) {
            oa._request= function( method, url, fo, bar, bleh, callback) {
              callback(null, "access_token=access&refresh_token=refresh");
            };
            oa.getOAuthAccessToken("", {}, function(error, access_token, refresh_token) {
              assert.equal( access_token, "access");
              assert.equal( refresh_token, "refresh");
            });
        },
        'we should correctly extract the token if received as a JSON literal': function (oa) {
          oa._request= function(method, url, headers, post_body, access_token, callback) {
            callback(null, '{"access_token":"access","refresh_token":"refresh"}');
          };
          oa.getOAuthAccessToken("", {}, function(error, access_token, refresh_token) {
            assert.equal( access_token, "access");
            assert.equal( refresh_token, "refresh");
          });
        },
        'we should return the received data to the calling method': function (oa) {
          oa._request= function(method, url, headers, post_body, access_token, callback) {
            callback(null, '{"access_token":"access","refresh_token":"refresh","extra_1":1, "extra_2":"foo"}');
          };
          oa.getOAuthAccessToken("", {}, function(error, access_token, refresh_token, results) {
            assert.equal( access_token, "access");
            assert.equal( refresh_token, "refresh");
            assert.isNotNull( results );
            assert.equal( results.extra_1, 1);
            assert.equal( results.extra_2, "foo");
          });
        }
    }
}).export(module);