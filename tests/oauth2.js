var vows = require('vows'),
    assert = require('assert'),
    OAuth2= require('../lib/oauth2').OAuth2;

vows.describe('OAuth2').addBatch({
    'Given an OAuth2 instance, ': {
      topic: new OAuth2(),
      'When handling the access token response': {
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
      },
      'When no grant_type parameter is specified': {
        'we should pass the value of the code argument as the code parameter': function(oa) {
          oa._request= function(method, url, headers, post_body, access_token, callback) {
            assert.isTrue( post_body.indexOf("code=xsds23") != -1 )
          }
          oa.getOAuthAccessToken("xsds23", {} );
        }
      },
      'When an invalid grant_type parameter is specified': {
        'we should pass the value of the code argument as the code parameter': function(oa) {
          oa._request= function(method, url, headers, post_body, access_token, callback) {
            assert.isTrue( post_body.indexOf("code=xsds23") != -1 )
          }
          oa.getOAuthAccessToken("xsds23", {grant_type:"refresh_toucan"} );
        }
      },
      'When a grant_type parameter of value "refresh_token" is specified': {
        'we should pass the value of the code argument as the refresh_token parameter, should pass a grant_type parameter, but shouldn\'t pass a code parameter' : function(oa) {
          oa._request= function(method, url, headers, post_body, access_token, callback) {
            assert.isTrue( post_body.indexOf("refresh_token=sdsds2") != -1 )
            assert.isTrue( post_body.indexOf("grant_type=refresh_token") != -1 )
            assert.isTrue( post_body.indexOf("code=") == -1 )
          }
          oa.getOAuthAccessToken("sdsds2", {grant_type:"refresh_token"} );
        }
      }
    }
}).export(module);